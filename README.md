# BHJL13- Efficient Cryptosystems From 2k-th Power Residue Symbols


## Setup

### Requirements
- `gcc`
- `make`
- `cmake`
- `gmp`

#### GNU Multi Precision
```shell script
 sudo apt install libgmp-dev
```

#### PBC

Downlaod `pbclib` from [here](https://crypto.stanford.edu/pbc/download.html)
```shell script
sudo apt install flex nettle-dev bison byacc
cd pbc-x.x.x
./configure
make -j9
make install
sudo ldconfig -v
```


## Build
```shell script
mkdir build
cd build
cmake ..
make -j9
```

## Run

### Tests
```shell script
cd build
./2k-prs-test [...args]
```


### Main
```shell script
cd build
./2k-prs [args]
```
## Clean

```shell script
rm -rf build
```
