#!/bin/sh

# Set up paths and environment for cross compiling for openwrt
export STAGING_DIR=/home/zhang/git/openwrt/openwrt-15.05-mesh/staging_dir
export TOOLCHAIN_DIR=$STAGING_DIR/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/
export LDCFLAGS=$TOOLCHAIN_DIR/lib
export LD_LIBRARY_PATH=$TOOLCHAIN_DIR/lib
export PATH=$TOOLCHAIN_DIR/bin:$PATH
