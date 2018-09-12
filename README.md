# sshMITM
a simple ssh MITM(man-in-the-middle) demo.Based on paramiko.

## useage
**Precondition**: A(a user) wants to connect to B(ssh server). We are now in the middle of the network link between A and B.

1. generate a pair of ssh key,change `Host_key = paramiko.RSAKey(filename="rsa")` 'rsa' to 'your private key file name'.
2. change target machine ip to B's ip.
3. set your iptables to forward network stream.
4. start this demo server.

## limits
This only works for users who ignore authenticate warning such as following:
```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the RSA key sent by the remote host is
SHA256:AUh+CTmEdgI3VuS81DYk7vqR6kBmywet4xExC0mniw4.
Please contact your system administrator.
Add correct host key in C:\\Users\\vv474/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in C:\\Users\\vv474/.ssh/known_hosts:28
RSA host key for 10.16.60.184 has changed and you have requested strict checking.
Host key verification failed.
```

and it can only work for password authentication, not for publickey authentication, because publickey authentication relys on session identifier which is related with negotiation.
