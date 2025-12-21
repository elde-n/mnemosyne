use std::{
    ffi::OsStr,
    io::{BufRead, BufReader},
    path::PathBuf,
};

pub struct Process {
    pub id: u64,
    pub base: u64,
    pub name: String,
}

fn process_from_path(path: PathBuf) -> Option<Process> {
    if !path.is_dir() {
        return None;
    }

    let file_name = path.file_name().and_then(OsStr::to_str)?;

    let Ok(id) = file_name.parse::<u64>() else {
        return None;
    };

    let Ok(name) = std::fs::read_to_string(path.join("comm")) else {
        return None;
    };

    let base = {
        let Ok(maps_file) = std::fs::File::open(path.join("maps")) else {
            return None;
        };

        let mut reader = BufReader::new(maps_file);
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;

        let Some(base) = line.split_once('-').map(|(base, _)| base) else {
            return None;
        };

        u64::from_str_radix(base, 16).ok()?
    };

    Some(Process {
        id,
        base,
        name: name.trim().to_string(),
    })
}

pub fn list() -> std::io::Result<Vec<Process>> {
    let mut processes = vec![];
    for entry in std::fs::read_dir("/proc")? {
        let path = entry?.path();
        let process = process_from_path(path);

        if let Some(process) = process {
            processes.push(process)
        }
    }

    Ok(processes)
}

pub fn from_id(id: u64) -> Option<Process> {
    let path = PathBuf::from(format!("/proc/{}", id));
    process_from_path(path)
}
