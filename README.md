
# Symmetrical Disguise: Realizing Homomorphic Encryption Services from Symmetric Primitives

A Symmetrical Disguise (SD) scheme  It is built on top of the SEAL (for HE) and PASTA (for HHE) libraries.

## Requirements
```
SEAL==4.0.0
CMAKE>=3.13
CPP==9.4.0
openssl>=3.0.10
```

## How to run
After cloning into the project, in the terminal, cd into the project and run:
```
cmake -S . -B build -DCMAKE_PREFIX_PATH=libs/seal
cmake --build build
```

cd into build folder. All executables are in this folder.
To run the schedule, execute:
```
./SDHHE 
```
Run this executable twice in order to create necessary files for the executable (it will fail in the first run)

To see the experiment, execute:
```
./SDHHEmultipleinput
```

Here you can find the link for the video: https://drive.google.com/file/d/10ftb2WjLivS8l5zB93aWZnfJNdwtrNOz/view?usp=drive_link
