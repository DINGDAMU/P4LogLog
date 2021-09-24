Citation
--------
```
@article{ding2021tracking,
  title={Tracking Normalized Network Traffic Entropy to Detect DDoS Attacks in P4},
  author={Ding, Damu and Savi, Marco and Siracusa, Domenico},
  journal={IEEE Transactions on Dependable and Secure Computing},
  year={2021},
  publisher={IEEE}
}
```

Installation
------------

1. Install [docker](https://docs.docker.com/engine/installation/) if you don't
   already have it.

2. Clone the repository to local 

    ```
    git clone https://github.com/DINGDAMU/P4LogLog.git    
    ```

3. ```
    cd P4LogLog
   ```

4. If you want, put the `p4app` script somewhere in your path. For example:

    ```
    cp p4app /usr/local/bin
    ```
    I have already modified the default docker image to **dingdamu/p4app-ddos:nwhhd**, so `p4app` script can be used directly.

P4LogLog
--------------

1.  ```
    ./p4app run p4loglog.p4app 
    ```
    After this step you'll see the terminal of **mininet**
2. Forwarding some packets in **mininet**

   ```
    pingall
    pingall
   ```
or 
   ```
    h1 ping h2 -c 12 -i 0.1
   ```



3. Enter p4loglog.p4app folder
   ```
    cd p4loglog.p4app 
   ```
4. Check the result by reading the register
   ```
    ./read_registers1.sh
    ./read_registers2.sh
    ./read_registers3.sh
   ```
 
 Register `hll_register` is the LogLog register.

 Register `hash_register[0]` represents the value in LogLog register of last incoming packet, and  `hash_register[1]` is the index in LogLog register. `hash_register[2]` is the queries cardinality from LogLog register.

