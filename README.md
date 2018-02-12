# Denial of Service abettor (DoSa)

Easy denial of service for people on the go.

This project already has an implementation [here](https://github.com/k4m4/kickthemout).
This is my implementation of it, with additional features to come. Hopefully.

## Planned Features
1. A TUI for seeing which hosts are on your subnet and selecting targets [[#3](/../../issues/3)]
    - along with vendor and OS details [[#2](/../../issues/2)] for each host
2. Minimal attack footprint [[#6](/../../issues/6)]
3. ARP spoof detection/mitigation [[#7](/../../issues/7)]

## Disclaimer
DoSa should only be used for educational purposes, or for testing with permission from the relevant authority.
The developer(s) will not be liable for any damages resulting from the use of this program.


### How to start development:
In case of Debian 8 download and install following packages:

vagrant: 
-  https://releases.hashicorp.com/vagrant/2.0.2/vagrant_2.0.2_i686.deb
virtualbox: 
- https://download.virtualbox.org/virtualbox/4.3.40/VirtualBox-4.3.40-110317-Linux_x86.run

Those are used to provide virtual image ready for testing and development.

In order to start just run:
`vagrant up`

Then connect into virtual machine:
`vagrant ssh`

When connected to system please note that `/vagrant` partition
is mounted to host system at same folder where `vagrant up` went up,
so development in your favourite IDE is still possible.

In order to test just go to '/vagrant' and all dosa files are there.
