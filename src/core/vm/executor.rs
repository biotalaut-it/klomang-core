use crate::core::state_manager::StateManager;
use crate::core::state::transaction::Address;
use crate::core::vm::gas_meter::{GasMeter, VMError};
use crate::core::state::storage::Storage;
use std::cell::RefCell;
use std::sync::Arc;

use wasmer::wasmparser::Operator;
use wasmer::{imports, CompilerConfig, Cranelift, EngineBuilder, Function, FunctionEnv, FunctionEnvMut, Instance, Module, RuntimeError, Store};
use wasmer_middlewares::metering::{get_remaining_points, set_remaining_points, Metering, MeteringPoints};

pub struct VMExecutor;

struct HostEnv<S: Storage + Clone + Send + Sync> {
    state_ptr: *mut StateManager<S>,
    gas: RefCell<GasMeter>,
    instance_backref: RefCell<Option<Instance>>,
}

unsafe impl<S: Storage + Clone + Send + Sync> Send for HostEnv<S> {}
unsafe impl<S: Storage + Clone + Send + Sync> Sync for HostEnv<S> {}

impl VMExecutor {
    fn wasm_meter_cost(operator: &Operator) -> u64 {
        GasMeter::opcode_cost(operator)
    }

    fn charge_metering_from_host(
        store: &mut impl wasmer::AsStoreMut,
        instance: &Instance,
        cost: u64,
    ) -> Result<(), VMError> {
        match get_remaining_points(store, instance) {
            MeteringPoints::Exhausted => Err(VMError::OutOfGas),
            MeteringPoints::Remaining(remaining) => {
                if remaining < cost {
                    Err(VMError::OutOfGas)
                } else {
                    set_remaining_points(store, instance, remaining - cost);
                    Ok(())
                }
            }
        }
    }

    pub fn execute<S>(
        wasm_bytes: &[u8],
        state_manager: &mut StateManager<S>,
        _sender: Address,
        gas_limit: u64,
    ) -> Result<u64, VMError>
    where
        S: Storage + Clone + Send + Sync + 'static,
    {
        let tree_snapshot = state_manager.tree.clone();

        let lm = GasMeter::new(gas_limit);
        let host_env = HostEnv {
            state_ptr: state_manager as *mut _,
            gas: RefCell::new(lm),
            instance_backref: RefCell::new(None),
        };

        // Charge intrinsic / payload before execution and enforce gas limit
        {
            let mut gas = host_env.gas.borrow_mut();
            gas.charge_intrinsic()?;
            gas.charge_payload(wasm_bytes)?;
        }

        let mut compiler = Cranelift::default();
        compiler.push_middleware(Arc::new(Metering::new(gas_limit, Self::wasm_meter_cost)));
        let engine = EngineBuilder::new(compiler).engine();

        let mut store = Store::new(&engine);
        let env = FunctionEnv::new(&mut store, host_env);

        let import_object = imports! {
            "env" => {
                "klomang_state_read" => Function::new_typed_with_env(
                    &mut store,
                    &env,
                    |mut ctx: FunctionEnvMut<HostEnv<S>>, key_ptr: i32, key_len: i32, out_ptr: i32, out_len: i32| -> Result<i32, RuntimeError> {
                        let (host_env, mut store_mut) = ctx.data_and_store_mut();
                        let mut gas = host_env.gas.borrow_mut();

                        // Charge host state read before operation
                        gas.charge_state_read().map_err(|_| RuntimeError::new("OutOfGas"))?;

                        // Adjust metering global so combined gas is correct
                        let instance = host_env
                            .instance_backref
                            .borrow()
                            .as_ref()
                            .ok_or_else(|| RuntimeError::new("Instance not initialized"))?
                            .clone();

                        Self::charge_metering_from_host(&mut store_mut, &instance, GasMeter::STATE_READ_COST)
                            .map_err(|_| RuntimeError::new("OutOfGas"))?;

                        // Read key/value from guest memory
                        let memory = instance
                            .exports
                            .get_memory("memory")
                            .map_err(|_| RuntimeError::new("Memory missing"))?;

                        let mut key = vec![0u8; key_len as usize];
                        memory
                            .view(&store_mut)
                            .read(key_ptr as u64, &mut key)
                            .map_err(|_| RuntimeError::new("Memory read failure"))?;

                        let state_manager = unsafe { &*host_env.state_ptr };
                        let key_bytes = if key_len as usize == 32 {
                            let mut fixed = [0u8; 32];
                            fixed.copy_from_slice(&key);
                            fixed
                        } else {
                            let hashed = blake3::hash(&key);
                            *hashed.as_bytes()
                        };

                        let value = state_manager
                            .state_read(key_bytes)
                            .map_err(|e| RuntimeError::new(format!("State read error: {}", e)))?;

                        if let Some(value) = value {
                            if value.len() > out_len as usize {
                                return Err(RuntimeError::new("Output buffer too small"));
                            }
                            memory
                                .view(&store_mut)
                                .write(out_ptr as u64, &value)
                                .map_err(|_| RuntimeError::new("Memory write failure"))?;
                            return Ok(value.len() as i32);
                        }

                        Ok(0)
                    },
                ),
                "klomang_state_write" => Function::new_typed_with_env(
                    &mut store,
                    &env,
                    |mut ctx: FunctionEnvMut<HostEnv<S>>, key_ptr: i32, key_len: i32, data_ptr: i32, data_len: i32| -> Result<i32, RuntimeError> {
                        let (host_env, mut store_mut) = ctx.data_and_store_mut();
                        let mut gas = host_env.gas.borrow_mut();

                        let memory_instance = host_env
                            .instance_backref
                            .borrow()
                            .as_ref()
                            .ok_or_else(|| RuntimeError::new("Instance not initialized"))?
                            .clone();

                        let memory = memory_instance
                            .exports
                            .get_memory("memory")
                            .map_err(|_| RuntimeError::new("Memory missing"))?;

                        let mut key = vec![0u8; key_len as usize];
                        memory
                            .view(&store_mut)
                            .read(key_ptr as u64, &mut key)
                            .map_err(|_| RuntimeError::new("Memory read failure"))?;

                        let mut data = vec![0u8; data_len as usize];
                        memory
                            .view(&store_mut)
                            .read(data_ptr as u64, &mut data)
                            .map_err(|_| RuntimeError::new("Memory read failure"))?;

                        let key_bytes = if key_len as usize == 32 {
                            let mut fixed = [0u8; 32];
                            fixed.copy_from_slice(&key);
                            fixed
                        } else {
                            let hashed = blake3::hash(&key);
                            *hashed.as_bytes()
                        };

                        let state_manager = unsafe { &mut *host_env.state_ptr };

                        let existing_value = state_manager
                            .state_read(key_bytes)
                            .map_err(|e| RuntimeError::new(format!("State read for write failed: {}", e)))?;

                        let is_new = existing_value.is_none();
                        gas.charge_state_write(is_new).map_err(|_| RuntimeError::new("OutOfGas"))?;

                        let state_write_cost = if is_new {
                            GasMeter::STATE_WRITE_NEW_COST
                        } else {
                            GasMeter::STATE_WRITE_UPDATE_COST
                        };

                        Self::charge_metering_from_host(&mut store_mut, &memory_instance, state_write_cost)
                            .map_err(|_| RuntimeError::new("OutOfGas"))?;

                        state_manager
                            .state_write(key_bytes, data)
                            .map_err(|e| RuntimeError::new(format!("State write failed: {}", e)))?;

                        Ok(1)
                    },
                ),
                "klomang_self_destruct" => Function::new_typed_with_env(
                    &mut store,
                    &env,
                    |mut ctx: FunctionEnvMut<HostEnv<S>>, key_ptr: i32, key_len: i32| -> Result<i32, RuntimeError> {
                        let (host_env, store_mut) = ctx.data_and_store_mut();
                        let mut gas = host_env.gas.borrow_mut();

                        let memory_instance = host_env
                            .instance_backref
                            .borrow()
                            .as_ref()
                            .ok_or_else(|| RuntimeError::new("Instance not initialized"))?
                            .clone();

                        let memory = memory_instance
                            .exports
                            .get_memory("memory")
                            .map_err(|_| RuntimeError::new("Memory missing"))?;

                        let mut key = vec![0u8; key_len as usize];
                        memory
                            .view(&store_mut)
                            .read(key_ptr as u64, &mut key)
                            .map_err(|_| RuntimeError::new("Memory read failure"))?;

                        let key_bytes = if key_len as usize == 32 {
                            let mut fixed = [0u8; 32];
                            fixed.copy_from_slice(&key);
                            fixed
                        } else {
                            let hashed = blake3::hash(&key);
                            *hashed.as_bytes()
                        };

                        let state_manager = unsafe { &mut *host_env.state_ptr };

                        // self-destruct does not charge extra, but gives refund
                        gas.refund_self_destruct();

                        let _ = state_manager.tree.prune_key(key_bytes);
                        Ok(1)
                    },
                ),
            }
        };

        let module = Module::new(&store, wasm_bytes).map_err(|e| VMError::WasmError(e.to_string()))?;

        let instance = Instance::new(&mut store, &module, &import_object).map_err(|e| {
            state_manager.tree = tree_snapshot.clone();
            VMError::RuntimeError(e.to_string())
        })?;

        // store instance reference for host functions to adjust metering
        env.as_ref(&store)
            .instance_backref
            .borrow_mut()
            .replace(instance.clone());

        // Precharge metering for intrinsic + payload
        let precharge = {
            let gas = env.as_ref(&store).gas.borrow();
            gas.consumed_host()
        };
        let remaining_for_wasm = gas_limit.saturating_sub(precharge);
        set_remaining_points(&mut store, &instance, remaining_for_wasm);

        let run_func = instance
            .exports
            .get_function("run")
            .map_err(|e| {
                state_manager.tree = tree_snapshot.clone();
                VMError::RuntimeError(e.to_string())
            })?;

        let result = run_func.call(&mut store, &[]);

        // break cycle and avoid leaks
        env.as_ref(&store).instance_backref.borrow_mut().take();

        match result {
            Ok(_) => {
                let points = get_remaining_points(&mut store, &instance);
                let remaining_points = match points {
                    MeteringPoints::Remaining(value) => value,
                    MeteringPoints::Exhausted => {
                        state_manager.tree = tree_snapshot;
                        return Err(VMError::OutOfGas);
                    }
                };

                let total_used = gas_limit.saturating_sub(remaining_points);
                let (net_used, _refund) = env.as_ref(&store).gas.borrow().finalize(total_used);
                Ok(net_used)
            }
            Err(e) => {
                state_manager.tree = tree_snapshot;
                let msg = e.to_string();
                if msg.contains("OutOfGas") || msg.contains("out of gas") {
                    Err(VMError::OutOfGas)
                } else {
                    Err(VMError::RuntimeError(msg))
                }
            }
        }
    }
}

