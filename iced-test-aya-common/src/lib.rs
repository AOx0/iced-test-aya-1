#![no_std]

use core::{
    fmt::{Debug, Display},
    ops::Not,
};

use bstr::ByteSlice;

#[repr(C)]
#[derive(Clone)]
pub struct Data {
    pub uid: u32,
    pub pid: u32,
    pub command: [u8; 16],
    // pub message: [u8; 11],
    pub path: [u8; 64],
}

impl Display for Data {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{uid: <6} {pid: <6}", uid = self.uid, pid = self.pid,)?;

        // write!(f, ", msg: ")?;
        // self.display_chars(f, &self.message)?;

        write!(f, ", cmd: ")?;
        self.display_chars(f, &self.command)?;

        write!(f, ", path: ")?;
        self.display_chars(f, &self.path)?;

        Ok(())
    }
}

impl Data {
    fn display_chars(&self, f: &mut core::fmt::Formatter, chars: &[u8]) -> core::fmt::Result {
        // let text = chars.split_once_str(&[0]).map(|a| a.0).unwrap_or(chars);

        for char in chars {
            if char.is_ascii().not() || char == &0 {
                continue;
            }

            let Some(char) = char::from_u32(*char as u32) else {
                continue;
            };
            write!(f, "{char}")?;
        }

        Ok(())
    }
}

impl Debug for Data {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{uid: <6} {pid: <6}, cmd: {cmd: <16}, path: {path}",
            uid = self.uid,
            pid = self.pid,
            // msg = self.message.as_bstr(),
            cmd = self.command.as_bstr(),
            path = self.path.as_bstr()
        )
    }
}
