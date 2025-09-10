# Spectre-PoC

This repository collects proof-of-concept (PoC) implementations for several vulnerabilities affecting modern x86 processors, including Spectre and Meltdown. The purpose is to facilitate academic research and technical understanding of these microarchitectural attacks.

## Contents

- **Bound-Check-Bypass/**：Spectre Variant 1
- **Branch-Target-Inject/**：Spectre Variant 2
- **Meltdown/**：Meltdown 
- **Speculative-Store-Bypass/**：Spectre Variant 4
- **SpectreRSB/**：Spectre Variant 5
- **tools/**：Auxiliary tools (assembly helpers, utility functions)

## How to Run

1. Install dependencies (example for Ubuntu):
   ```sh
   sudo apt update
   sudo apt install build-essential
   ```

2. Build the PoC: Enter the desired subdirectory and run make to generate the PoC executable:
   ```sh
   cd Bound-Check-Bypass
   make
   ```

3. Execute the PoC：
   - **If the code binds to a specific CPU (requires root privileges):**
   ```sh
   sudo ./Poc
   ```
   - **If the code does not specify a CPU (recommended to bind to a specific core):**
   ```sh
   taskset -c 1 ./Poc
   ```
4. Repeat the above steps for other PoC directories as needed.

## 注意事项

- For research and educational purposes only. Do not run on production systems or unauthorized devices.
- Some PoCs may require root privileges or specific hardware support.
- Results may vary depending on CPU model, kernel version, and system configuration.

## References

- [Spectre & Meltdown Official Documentation](https://spectreattack.com/)
