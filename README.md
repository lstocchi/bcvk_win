# bcvk_win

**Bootc Virtualization Kit for Windows** - A proof-of-concept Windows port of bcvk for managing bootc containers with Hyper-V.

## Demo

Watch a quick demonstration of bcvk_win in action:

[![bcvk_win Demo](https://img.youtube.com/vi/VT_2Vp4BqhM/0.jpg)](https://youtu.be/VT_2Vp4BqhM)

## ⚠️ Important Notice

This is a **quick proof-of-concept** developed during DevTools Week. It requires a **customized environment** to function and is not intended for general use.

## Credits

This project is a Windows port/adaptation of [bcvk](https://github.com/bootc-dev/bcvk) (Bootc Virtualization Kit). Most of the core codebase has been adapted from the original bcvk project, with modifications to support Hyper-V on Windows instead of the Linux/QEMU-based approach.

**Original Project**: [bootc-dev/bcvk](https://github.com/bootc-dev/bcvk)

## Prerequisites

This POC requires several custom components and specific environment setup:

### 1. Hyper-V Administrator Access
- The user must be a member of the **Hyper-V Administrators** group
- This is required for creating and managing Hyper-V virtual machines

### 2. Custom Bootc Image
- Requires a **custom bootc container image** that includes:
  - **cloud-init** support for VM initialization
  - **hyperv-daemons** for Hyper-V integration
- Standard bootc images will not work with this POC

### 3. Custom User-Data File
- Uses a custom cloud-init `user-data` file located at `crates/kit/scripts/user-data`
- This file configures SSH access and user setup for the VMs
- The file is automatically located relative to the project root

### 4. Additional Dependencies
- **macadam**: A tool for managing Hyper-V VMs
- **podman**: For container image management

## What It Does

`bcvk_win` provides a Windows-native interface for:
- Creating and managing bootc-based virtual machines on Hyper-V
- Installing bootc container images to disk images
- Running ephemeral VMs from bootc container images

## Usage

```bash
# Run a bootc image as an ephemeral Hyper-V VM
bcvk_win hyperv run <image> [options]

# Install a bootc image to a disk image
bcvk_win to-disk <image> <output-disk> [options]
```

## Project Structure

- `crates/kit/src/` - Main application code
- `crates/kit/src/hyperv/` - Hyper-V integration
- `crates/kit/scripts/user-data` - Custom cloud-init configuration

## Limitations

- **POC Status**: This is experimental code, not production-ready
- **Custom Environment Required**: Will not work with standard bootc images or default configurations
- **Windows-Specific**: Designed specifically for Windows with Hyper-V
- **Hardcoded Paths**: Some paths (like SSH keys) may be hardcoded for the development environment

## Development



## License

This project should be licensed in accordance with the original [bcvk](https://github.com/bootc-dev/bcvk) project's license. Please check the original repository for license details and ensure compliance when using or distributing this code.