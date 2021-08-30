## test record
### ins
```
# compile
cp /root/flowcontrol/flowcontrol.p4 $SDE/pkgsrc/p4-examples/p4_16_programs/flowcontrol

cd $SDE/pkgsrc/p4-build/

./configure --prefix=$SDE_INSTALL --with-tofino --with-bf-runtime P4_NAME=flowcontrol P4_PATH=/root/SDE-source/bf-sde-9.2.0/pkgsrc/p4-examples/p4_16_programs/flowcontrol/flowcontrol.p4 P4_VERSION=p4-16 P4C=p4c --enable-thrift

make

make install

```