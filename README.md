# PinDown

PinDown enhances Access Control in Linux systems by making use of LSM framework. Apart from file permissions, it uses extended attributes to identify which programs are allowed to access the file. Only program which is specified in an extended attribute of a file is allowed to access it. All other programs which try to access the file are denied access.

## Installation

This repo contains the source for a kernel module which could be built along with Linux Kernel. Due to complications of using LSM framework on latest Ubuntu machines, this module is tested on Ubuntu 8.04 with Linux Kernel v2.6.23. Once the kernel is built and installed, the module can be built by copying **Makefile** and **pindown.c** to **<linux_kernel_source>/security** directory and then running **make** command. Once built, module can be inserted into kernel using **insmod** command. The program **attr** is used to set an extended attribute on a file. Use following command to set an extended attribute on a file.

```bash
setfattr -n "security.pindown" -v "/bin/cat\0" <filename>
```

This attribute tells PinDown that the <filename> could be only accessed by the program */bin/cat*

