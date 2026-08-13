use std::{fs::File, io::Read, path::Path};

use futures_util::TryStreamExt;
use l2_loop_core::{
    AgentResult, DeploymentAuthorizationV1, DeploymentHostCompatibilityV1, InterfaceKind,
    InterfaceName, PreflightReport,
};
use rtnetlink::packet_route::{
    link::{LinkAttribute, LinkMessage},
    route::{RouteAttribute, RouteMessage},
    tc::TcAttribute,
};

use crate::{
    DeploymentIoError, DeploymentPlatformInspector, DeploymentPlatformSnapshotV1,
    PlatformInspector, PreflightService,
};

use super::{
    inspector::{SystemLinuxInspector, link_record, run_async},
    interface::classify_interface,
};

const PACKET_TABLE_PATH: &str = "/proc/net/packet";
const MAX_PACKET_TABLE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentLinkSnapshotV1 {
    pub name: InterfaceName,
    pub ifindex: u32,
    pub kind: InterfaceKind,
    pub administrative_up: bool,
    pub operational_up: bool,
    pub master_ifindex: Option<u32>,
    pub peer_or_namespace_relation_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentConsumerSnapshotV1 {
    pub tc_clsact_present: bool,
    pub address_present: bool,
    pub route_present: bool,
    pub neighbor_present: bool,
    pub service_present: bool,
    pub other_consumer_present: bool,
    pub logical_cpu_count: u32,
}

pub trait DeploymentCandidateSource {
    fn inspect_identity(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<DeploymentLinkSnapshotV1, DeploymentIoError>;

    fn inspect_consumers(
        &mut self,
        interface: &InterfaceName,
        ifindex: u32,
    ) -> Result<DeploymentConsumerSnapshotV1, DeploymentIoError>;
}

pub struct LinuxDeploymentPlatformInspector<P, S> {
    preflight: PreflightService<P>,
    source: S,
}

impl<P, S> LinuxDeploymentPlatformInspector<P, S>
where
    P: PlatformInspector,
    S: DeploymentCandidateSource,
{
    pub fn new(preflight: P, source: S) -> Self {
        Self {
            preflight: PreflightService::new(preflight),
            source,
        }
    }
}

impl<P, S> DeploymentPlatformInspector for LinuxDeploymentPlatformInspector<P, S>
where
    P: PlatformInspector,
    S: DeploymentCandidateSource,
{
    fn inspect_authorized_interface(
        &mut self,
        authorization: &DeploymentAuthorizationV1,
    ) -> Result<DeploymentPlatformSnapshotV1, DeploymentIoError> {
        let requested = InterfaceName::new(authorization.interface.name.as_str())
            .map_err(|_| DeploymentIoError::Unavailable)?;
        let before = self.source.inspect_identity(&requested)?;
        if before.name != requested || before.ifindex != authorization.interface.ifindex {
            return Err(DeploymentIoError::Unavailable);
        }

        let preflight = match self
            .preflight
            .execute(&requested)
            .map_err(|_| DeploymentIoError::Unavailable)?
        {
            AgentResult::Preflight { report } => report,
            _ => return Err(DeploymentIoError::Unavailable),
        };
        if !preflight_matches_link(&preflight, &before) {
            return Err(DeploymentIoError::Unavailable);
        }

        let consumers = self.source.inspect_consumers(&requested, before.ifindex)?;
        let after = self.source.inspect_identity(&requested)?;
        if before != after {
            return Err(DeploymentIoError::Unavailable);
        }

        let host = DeploymentHostCompatibilityV1::new(
            preflight.kernel.architecture.as_str(),
            preflight.kernel.release.as_str(),
            consumers.logical_cpu_count,
        )
        .map_err(|_| DeploymentIoError::Unavailable)?;

        Ok(DeploymentPlatformSnapshotV1 {
            preflight,
            interface_name: after.name,
            ifindex: after.ifindex,
            kind: after.kind,
            administrative_up: after.administrative_up,
            operational_up: after.operational_up,
            master_ifindex: after.master_ifindex,
            tc_clsact_present: consumers.tc_clsact_present,
            address_present: consumers.address_present,
            route_present: consumers.route_present,
            neighbor_present: consumers.neighbor_present,
            service_present: consumers.service_present,
            other_consumer_present: consumers.other_consumer_present
                || after.peer_or_namespace_relation_present,
            host,
        })
    }
}

fn preflight_matches_link(report: &PreflightReport, link: &DeploymentLinkSnapshotV1) -> bool {
    report.interface.requested.name == link.name
        && report.interface.requested.ifindex == link.ifindex
        && report.interface.kind == link.kind
        && report.interface.admin_up == link.administrative_up
        && report.interface.oper_up == link.operational_up
        && report
            .interface
            .master
            .as_ref()
            .map(|master| master.ifindex)
            == link.master_ifindex
}

#[derive(Debug, Default)]
pub struct SystemDeploymentCandidateSource;

impl DeploymentCandidateSource for SystemDeploymentCandidateSource {
    fn inspect_identity(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<DeploymentLinkSnapshotV1, DeploymentIoError> {
        let name = interface.as_str().to_owned();
        run_async(move || async move {
            let (connection, handle, _) =
                rtnetlink::new_connection().map_err(|_| unavailable_inspector_error())?;
            tokio::spawn(connection);
            let mut messages = handle.link().get().match_name(name).execute();
            let message = messages
                .try_next()
                .await
                .map_err(|_| unavailable_inspector_error())?
                .ok_or_else(unavailable_inspector_error)?;
            if messages
                .try_next()
                .await
                .map_err(|_| unavailable_inspector_error())?
                .is_some()
            {
                return Err(unavailable_inspector_error());
            }
            deployment_link_snapshot(message).ok_or_else(unavailable_inspector_error)
        })
        .map_err(|_| DeploymentIoError::Unavailable)
    }

    fn inspect_consumers(
        &mut self,
        _interface: &InterfaceName,
        ifindex: u32,
    ) -> Result<DeploymentConsumerSnapshotV1, DeploymentIoError> {
        let service_present = packet_socket_present(Path::new(PACKET_TABLE_PATH), ifindex)?;
        let logical_cpu_count = std::thread::available_parallelism()
            .ok()
            .and_then(|count| u32::try_from(count.get()).ok())
            .filter(|count| *count != 0)
            .ok_or(DeploymentIoError::Unavailable)?;
        let observed = run_async(move || inspect_netlink_consumers(ifindex))
            .map_err(|_| DeploymentIoError::Unavailable)?;

        Ok(DeploymentConsumerSnapshotV1 {
            tc_clsact_present: observed.tc_clsact_present,
            address_present: observed.address_present,
            route_present: observed.route_present,
            neighbor_present: observed.neighbor_present,
            service_present,
            other_consumer_present: false,
            logical_cpu_count,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetlinkConsumerSnapshot {
    tc_clsact_present: bool,
    address_present: bool,
    route_present: bool,
    neighbor_present: bool,
}

async fn inspect_netlink_consumers(
    ifindex: u32,
) -> Result<NetlinkConsumerSnapshot, super::inspector::InspectorError> {
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|_| unavailable_inspector_error())?;
    tokio::spawn(connection);

    let mut addresses = handle
        .address()
        .get()
        .set_link_index_filter(ifindex)
        .execute();
    let mut address_present = false;
    while addresses
        .try_next()
        .await
        .map_err(|_| unavailable_inspector_error())?
        .is_some()
    {
        address_present = true;
    }

    let mut routes = handle.route().get(RouteMessage::default()).execute();
    let mut route_present = false;
    while let Some(route) = routes
        .try_next()
        .await
        .map_err(|_| unavailable_inspector_error())?
    {
        route_present |= route_uses_interface(&route, ifindex);
    }

    let mut neighbors = handle.neighbours().get().execute();
    let mut neighbor_present = false;
    while let Some(neighbor) = neighbors
        .try_next()
        .await
        .map_err(|_| unavailable_inspector_error())?
    {
        neighbor_present |= neighbor.header.ifindex == ifindex;
    }

    let mut qdiscs = handle.qdisc().get().index(ifindex as i32).execute();
    let mut tc_clsact_present = false;
    while let Some(qdisc) = qdiscs
        .try_next()
        .await
        .map_err(|_| unavailable_inspector_error())?
    {
        tc_clsact_present |= qdisc
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, TcAttribute::Kind(kind) if kind == "clsact"));
    }

    Ok(NetlinkConsumerSnapshot {
        tc_clsact_present,
        address_present,
        route_present,
        neighbor_present,
    })
}

fn deployment_link_snapshot(message: LinkMessage) -> Option<DeploymentLinkSnapshotV1> {
    let peer_or_namespace_relation_present = message.attributes.iter().any(|attribute| {
        matches!(
            attribute,
            LinkAttribute::Link(_) | LinkAttribute::LinkNetNsId(_)
        )
    });
    let record = link_record(message)?;
    Some(DeploymentLinkSnapshotV1 {
        kind: classify_interface(&record),
        name: record.name,
        ifindex: record.ifindex,
        administrative_up: record.admin_up,
        operational_up: record.oper_up,
        master_ifindex: record.master_ifindex,
        peer_or_namespace_relation_present,
    })
}

fn route_uses_interface(route: &RouteMessage, ifindex: u32) -> bool {
    route.attributes.iter().any(|attribute| match attribute {
        RouteAttribute::Oif(output) => *output == ifindex,
        RouteAttribute::MultiPath(next_hops) => next_hops
            .iter()
            .any(|next_hop| next_hop.interface_index == ifindex),
        _ => false,
    })
}

fn packet_socket_present(path: &Path, ifindex: u32) -> Result<bool, DeploymentIoError> {
    let file = File::open(path).map_err(|_| DeploymentIoError::Unavailable)?;
    let mut bytes = Vec::new();
    file.take(MAX_PACKET_TABLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DeploymentIoError::Unavailable)?;
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|length| length > MAX_PACKET_TABLE_BYTES)
    {
        return Err(DeploymentIoError::Unavailable);
    }
    let text = String::from_utf8(bytes).map_err(|_| DeploymentIoError::Unavailable)?;
    parse_packet_socket_table(&text, ifindex)
}

fn parse_packet_socket_table(text: &str, ifindex: u32) -> Result<bool, DeploymentIoError> {
    let mut lines = text.lines();
    let header = lines.next().ok_or(DeploymentIoError::Unavailable)?;
    if header.split_whitespace().collect::<Vec<_>>()
        != [
            "sk", "RefCnt", "Type", "Proto", "Iface", "R", "Rmem", "User", "Inode",
        ]
    {
        return Err(DeploymentIoError::Unavailable);
    }

    let mut present = false;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() != 9 {
            return Err(DeploymentIoError::Unavailable);
        }
        let observed_ifindex = columns[4]
            .parse::<u32>()
            .map_err(|_| DeploymentIoError::Unavailable)?;
        present |= observed_ifindex == ifindex;
    }
    Ok(present)
}

fn unavailable_inspector_error() -> super::inspector::InspectorError {
    super::inspector::InspectorError::new("deployment platform input is unavailable")
}

pub type SystemLinuxDeploymentPlatformInspector =
    LinuxDeploymentPlatformInspector<SystemLinuxInspector, SystemDeploymentCandidateSource>;

impl LinuxDeploymentPlatformInspector<SystemLinuxInspector, SystemDeploymentCandidateSource> {
    pub fn system() -> Self {
        Self::new(
            SystemLinuxInspector::system(),
            SystemDeploymentCandidateSource,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "sk RefCnt Type Proto Iface R Rmem User Inode\n";

    #[test]
    fn packet_table_reports_only_exact_interface_presence() {
        let table = format!(
            "{EMPTY}ffff000000000001 3 3 0003 7 1 0 0 41\n\
             ffff000000000002 3 3 0003 8 1 0 0 42\n"
        );

        assert_eq!(parse_packet_socket_table(&table, 7), Ok(true));
        assert_eq!(parse_packet_socket_table(&table, 9), Ok(false));
    }

    #[test]
    fn packet_table_rejects_ambiguous_shapes() {
        for table in [
            "",
            "unexpected header\n",
            "sk RefCnt Type Proto Iface R Rmem User Inode\nbroken\n",
            "sk RefCnt Type Proto Iface R Rmem User Inode\na b c d secret f g h i\n",
        ] {
            assert_eq!(
                parse_packet_socket_table(table, 7),
                Err(DeploymentIoError::Unavailable)
            );
        }
    }
}
