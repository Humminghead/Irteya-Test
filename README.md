# Irtea test application
 
 Usage:
  app  [--ip_dst] [--tcp_sp] [--ip_src] [--tcp_dp] [--file | --config]
 
  Examples:
 
  app --ip_dst 10.1.1.101 --tcp_sp 80 --ip_src 10.1.1.1 --tcp_dp 3200 --file /tmp/http_with_jpegs.cap
 
 
  app --config /tmp/config/run.json
 
  Config example:
  ```json
    {
       "handlers":[
          {
             "traffic_source":"file",
             "pcap_file":"/tmp/http_with_jpegs.cap",
             "filter":"ip and src 10.1.1.1 and dst 10.1.1.101 and tcp and src port 80 and dst port 3200"
          }
       ]
    }
```
## Build how-to:

```
git clone https://github.com/Humminghead/Irteya-Test.git
cd Irteya-Test/
cmake ./CMakeLists.txt -DCMAKE_C_COMPILER=/usr/bin/gcc-11 -DCMAKE_CXX_COMPILER=/usr/bin/g++-11 
cmake --build . -j16
ls -la
-rwxrwxr-x  1 user user 1546112 Jun  3 12:26 irteya-test

```
 
