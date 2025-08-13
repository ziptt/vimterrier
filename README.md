
Vimterrier editor
--------------
Text editor with Vim's encryption, for Linux. Forked from [l3afpad](https://github.com/stevenhoneyman/l3afpad) and added encryption

### How to use
Download latest vimterrier.zip from "Releases", unzip, run vimterrier

### Build from source
Vimterrier requires:
* GTK+-3.x.x libraries
* ncurses library
* sodium library

and for building also:
* automake
* intltool

Simple compile and install procedure:
```
[ For Ubuntu ]
$ apt install automake intltool libgtk-3-dev libsodium-dev
$ unzip main.zip                      # unpack the sources
$ cd vimterrier-main                  # change to the toplevel directory
$ ./autogen.sh                        # generate the `configure' script
$ ./configure                         # run the `configure' script
$ make                                # build Vimterrier
[ Become root if necessary ]
# make install-strip                  # install Vimterrier
```
