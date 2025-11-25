use crate::to_disk::ToDiskOpts;
use color_eyre::Result;

pub fn run(_opts: ToDiskOpts) -> Result<()> {
    Err(color_eyre::eyre::eyre!(
        "Disk installation is not yet implemented."
    ))
}
