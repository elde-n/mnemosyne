use crate::module;

pub struct Detour {
    hook_pointer: u64,
    original_pointer: u64,
    original_bytes: [u8; 12],
    is_hooked: bool,
}

impl Detour {
    pub fn new(original: u64, hook: u64) -> Option<Self> {
        let mut detour = Self {
            hook_pointer: hook,
            original_pointer: original,
            original_bytes: [0; 12],
            is_hooked: false,
        };

        if !detour.save() || !detour.hook() {
            return None;
        }

        Some(detour)
    }

    fn hook(&mut self) -> bool {
        let mut jump = [
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0,
        ];

        let hook_address = self.hook_pointer;
        jump[2..10].copy_from_slice(&hook_address.to_le_bytes());

        match module::write(self.original_pointer, &jump) {
            Ok(_) => {
                self.is_hooked = true;
                true
            }

            Err(_) => false,
        }
    }

    pub fn unhook(&mut self) -> bool {
        if self.is_hooked {
            self.is_hooked = false;
            return self.restore();
        }

        true
    }

    fn save(&mut self) -> bool {
        let result = module::read::<[u8; 12]>(self.original_pointer);
        if result.is_none() {
            return false;
        }

        self.original_bytes = result.unwrap();
        true
    }

    fn restore(&self) -> bool {
        match module::write(self.original_pointer, &self.original_bytes) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn call_original<R, Args>(&mut self, args: Args) -> Result<R, &str> {
        if !self.unhook() {
            return Err("failed to unhook detour");
        }

        let result = unsafe {
            std::mem::transmute::<_, extern "C" fn(Args) -> R>(self.original_pointer)(args)
        };

        if !self.hook() {
            return Err("failed to re-hook detour");
        }

        Ok(result)
    }
}

impl Default for Detour {
    fn default() -> Self {
        return unsafe { std::mem::MaybeUninit::<Self>::zeroed().assume_init() };
    }
}

impl Drop for Detour {
    fn drop(&mut self) {
        if self.hook_pointer == 0 {
            return;
        }

        self.unhook();
    }
}
