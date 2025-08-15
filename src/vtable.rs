use crate::module;

pub struct VTable {
    method_index: u64,
    original_pointer: u64,
    original_method: u64,

    pub is_hooked: bool,
}

impl VTable {
    pub fn new(original: u64, index: u64) -> Self {
        Self {
            method_index: index,
            original_pointer: original,
            original_method: 0,

            is_hooked: false,
        }
    }

    pub fn set_hook(&mut self, hook: u64) -> Result<(), String> {
        let vmt = module::read::<*mut u64>(self.original_pointer).unwrap();

        self.original_method = unsafe {
            let result = module::read::<u64>(vmt.add(self.method_index as usize) as u64);
            if result.is_none() {
                return Err("invalid method index".into());
            }

            result.unwrap()
        };

        let result = unsafe { module::write(vmt.add(self.method_index as usize) as u64, &hook) };
        if result.is_ok() {
            self.is_hooked = true;
        }

        result
    }

    pub fn unhook(&mut self) -> Result<(), String> {
        let vmt = module::read::<*mut u64>(self.original_pointer).unwrap();
        let result = unsafe {
            module::write(
                vmt.add(self.method_index as usize) as u64,
                &(self.original_method),
            )
        };

        if result.is_ok() {
            self.is_hooked = false;
        }

        result
    }

    pub fn call_original<R, Args>(&mut self, args: Args) -> R {
        unsafe { std::mem::transmute::<_, extern "C" fn(Args) -> R>(self.original_method)(args) }
    }
}
