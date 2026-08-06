use l2_loop_core::PinRootState;

const STANDARD_BPFFS_MOUNTPOINT: &str = "/sys/fs/bpf";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtfSnapshot {
    pub exists: bool,
    pub regular_file: bool,
    pub readable: bool,
}

impl BtfSnapshot {
    pub const fn is_readable(self) -> bool {
        self.exists && self.regular_file && self.readable
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRootSnapshot {
    Absent,
    Present {
        entry_count: usize,
        ownership_valid: bool,
    },
}

impl PinRootSnapshot {
    pub const fn absent() -> Self {
        Self::Absent
    }

    pub const fn empty() -> Self {
        Self::Present {
            entry_count: 0,
            ownership_valid: false,
        }
    }

    pub const fn owned(entry_count: usize) -> Self {
        Self::Present {
            entry_count,
            ownership_valid: true,
        }
    }

    pub const fn foreign(entry_count: usize) -> Self {
        Self::Present {
            entry_count,
            ownership_valid: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForeignPinSummary {
    pub top_level_root_count: usize,
    pub has_foreign_roots: bool,
}

pub fn bpffs_mounted_at_standard_path(snapshot: &str) -> bool {
    snapshot.lines().any(|line| {
        let mut fields = line.split_ascii_whitespace();
        matches!(
            (fields.nth(1), fields.next()),
            (Some(STANDARD_BPFFS_MOUNTPOINT), Some("bpf"))
        )
    })
}

pub const fn classify_pin_root(snapshot: PinRootSnapshot) -> PinRootState {
    match snapshot {
        PinRootSnapshot::Absent => PinRootState::Absent,
        PinRootSnapshot::Present { entry_count: 0, .. } => PinRootState::Empty,
        PinRootSnapshot::Present {
            ownership_valid: true,
            ..
        } => PinRootState::Owned,
        PinRootSnapshot::Present { .. } => PinRootState::Foreign,
    }
}

pub fn summarize_foreign_top_level_roots<I, S>(
    roots: I,
    owned_root: &str,
) -> ForeignPinSummary
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let top_level_root_count = roots
        .into_iter()
        .filter(|root| root.as_ref() != owned_root)
        .count();

    ForeignPinSummary {
        top_level_root_count,
        has_foreign_roots: top_level_root_count > 0,
    }
}
