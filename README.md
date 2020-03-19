# lifesaverc
lifesaverc is a C program that compresses a file/directory and sends it to a backup server through a ssh tunel.

## Usage
The following example uses bz2 compression algorithm by default and only logs error messages.

    lifesaverc -f myfile -o myfile.tar.bz2

If you want more log messages, use the -v option to increase the log level.

    lifesaverc -f myfile -o myfile.tar.bz2 -vvv

You can choose the compression algorithm.

    lifesaverc -jf myfile -o myfile.tar.bz2 -vvv

or

    lifesaverc -zf myfile -o myfile.tar.gz -vvv

For further details use the -h option

    lifesaverc -h

## Dependencies
Fedora

    sudo dnf install libarchive-devel libssh-devel

Debian/Ubuntu

    sudo apt install libarchive-dev libssh-dev

## Building from code
Create a build directory, where all objects files will be at.

    mkdir build
    cd build

Then, check if your system has all required dependencies, compile and install lifesaverc. You can define the compiler to use by setting **CMAKE_C_COMPILER**. For example:**cmake -DCMAKE_C_COMPILER=clang**.

    cmake ..
    make
    sudo make install

## Installation using rpm packages
Install the rpm package that can be found on releases files or enable this repository.

    dnf copr enable thynkon/lifesaverc
    dnf install lifesaverc

For more details about lifesaverc build status refer to [lifesaverc copr repository](https://copr.fedorainfracloud.org/coprs/thynkon/lifesaverc).

## License
This program is under the [GPLv3 License](LICENSE).
