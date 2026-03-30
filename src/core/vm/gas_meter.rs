pub type GasCost = u64;

#[derive(Debug, Clone)]
pub struct GasMeter {
    pub initial: i128,
    pub remaining: i128,
    pub consumed_wasm: u64,
    pub consumed_host: u64,
    pub refund: u64,
}

impl GasMeter {
    pub const INTRINSIC_GAS: GasCost = 21_000;
    pub const STATE_READ_COST: GasCost = 2_100;
    pub const STATE_WRITE_NEW_COST: GasCost = 20_000;
    pub const STATE_WRITE_UPDATE_COST: GasCost = 5_000;
    pub const SELF_DESTRUCT_REFUND: GasCost = 24_000;

    pub fn new(gas_limit: GasCost) -> Self {
        Self {
            initial: gas_limit as i128,
            remaining: gas_limit as i128,
            consumed_wasm: 0,
            consumed_host: 0,
            refund: 0,
        }
    }

    pub fn charge_intrinsic(&mut self) -> Result<(), VMError> {
        self.consume_host(GasMeter::INTRINSIC_GAS)
    }

    pub fn charge_payload(&mut self, payload: &[u8]) -> Result<(), VMError> {
        let mut total_cost: u64 = 0;
        for byte in payload {
            total_cost = total_cost.saturating_add(if *byte == 0 { 4 } else { 16 });
        }
        self.consume_host(total_cost)
    }

    pub fn charge_state_read(&mut self) -> Result<(), VMError> {
        self.consume_host(GasMeter::STATE_READ_COST)
    }

    pub fn charge_state_write(&mut self, is_new: bool) -> Result<(), VMError> {
        let cost = if is_new {
            GasMeter::STATE_WRITE_NEW_COST
        } else {
            GasMeter::STATE_WRITE_UPDATE_COST
        };
        self.consume_host(cost)
    }

    pub fn charge_wasm(&mut self, cost: GasCost) -> Result<(), VMError> {
        self.consume_host(cost)?;
        self.consumed_wasm = self.consumed_wasm.saturating_add(cost);
        Ok(())
    }

    pub fn refund_self_destruct(&mut self) {
        self.refund = self.refund.saturating_add(GasMeter::SELF_DESTRUCT_REFUND);
    }

    pub fn consume_host(&mut self, cost: GasCost) -> Result<(), VMError> {
        self.remaining -= cost as i128;
        self.consumed_host = self.consumed_host.saturating_add(cost);
        if self.remaining < 0 {
            Err(VMError::OutOfGas)
        } else {
            Ok(())
        }
    }

    pub fn consume_opcode(&mut self, opcode_cost: GasCost) -> Result<(), VMError> {
        self.remaining -= opcode_cost as i128;
        self.consumed_wasm = self.consumed_wasm.saturating_add(opcode_cost);
        if self.remaining < 0 {
            Err(VMError::OutOfGas)
        } else {
            Ok(())
        }
    }

    pub fn get_used(&self) -> u64 {
        (self.initial - self.remaining) as u64
    }

    pub fn consumed_host(&self) -> u64 {
        self.consumed_host
    }

    pub fn finalize(&self, total_used: u64) -> (u64, u64) {
        let max_refund = total_used / 5; // 20%
        let actual_refund = self.refund.min(max_refund);
        let net_used = total_used.saturating_sub(actual_refund);
        (net_used, actual_refund)
    }

    pub fn opcode_cost(operator: &wasmer::wasmparser::Operator) -> GasCost {
        use wasmer::wasmparser::Operator;

        match operator {
            Operator::I32Add { .. } | Operator::I32Sub { .. } | Operator::I32Mul { .. }
            | Operator::I64Add { .. } | Operator::I64Sub { .. } | Operator::I64Mul { .. } => 3,

            Operator::I32DivS { .. } | Operator::I32DivU { .. } | Operator::I64DivS { .. }
            | Operator::I64DivU { .. } | Operator::F32Sqrt { .. } | Operator::F64Sqrt { .. } => 10,

            Operator::I32Load { .. } | Operator::I64Load { .. }
            | Operator::F32Load { .. } | Operator::F64Load { .. }
            | Operator::I32Store { .. } | Operator::I64Store { .. }
            | Operator::F32Store { .. } | Operator::F64Store { .. } => 3,

            Operator::Call { .. } => 20,
            Operator::CallIndirect { .. } => 40,
            Operator::MemoryCopy { .. } | Operator::MemoryFill { .. } => 50,
            _ => 1,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VMError {
    #[error("Out of gas")]
    OutOfGas,
    #[error("Runtime error: {0}")]
    RuntimeError(String),
    #[error("State access error: {0}")]
    StateError(String),
    #[error("WASM error: {0}")]
    WasmError(String),
}
