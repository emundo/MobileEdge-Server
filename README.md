#MobileEdge Server Framework
This is the Node.js implementation of the MobileEdge server framework
developed at e-Mundo as part of a research project. We will make
some documentation about the MobileEdge project available as
soon as possible.

The MobileEdge server framework is still under development and
should __not__ (yet) be used in productive environments. However,
we encourage you to contribute ideas and code if you feel like it!

##News
The last bulk of changes made was a result of rethinking our design
during the implementation of the first 
[client side framework for iOS](https://github.com/emundo/MobileEdge-iOS).
The MobileEdge-Server component now functions as a proxy to the
backend, forwarding any encrypted requests it receives after
decrypting them. It also takes care of key exchange and prekey
storage and handout. We currently provide a version 0.1 of
our API which is prone to be changed in the future.

##Dependencies
At the moment, the server framework requires Node.js and
MongoDB to be installed. Tests run fine under Node.js v0.11.13.
We have had some trouble (segmentation faults we found difficult to diagnose) 
on Node.js v0.10.31 on Mac OS X, so we recommend using Node v0.11.13.

We have migrated from [js-nacl](https://github.com/tonyg/js-nacl) to
[node-sodium](https://github.com/paixaop/node-sodium). Some work needs
to be done to compile node-sodium for node v0.11.x. It basically boils
down to applying the patches from [this](https://github.com/paixaop/node-sodium/pull/27)
pull-request to the node-sodium code which you might need to 
clone separately, patch, and move into the node-modules directory. 
Hopefully, this will not be necessary for long, if the pull request 
gets merged into the node-sodium repository.

##Installation
Installation should be possible just cloning the Github repository
and, in the `MobileEdge-Server/node/` directory, typing 

```
npm install
```

##Troubleshooting
We have mostly tested installation and running the MobileEdge server
on Ubuntu and Mac OS X systems. If you encounter any problems on
these or different achitectures, let us know. We will do our
best to help identify the problem.

Some problems we had at some point are:

###MongoDB installation fails (GPG-Key trouble)
Use the `mongodb-gpgkey` included in this repository (add it to
APT using `apt-key add mongodb-gpgkey`).

##TODO
There is quite a few things which need to be done at some point:
* Thorough code cleanup, extracting some of the stuff in main into  
  separate modules.
* Put some thought into the obvious security implications when storing  
  keys using JavaScript and MongoDB. Securely erase memory that was used  
  for key storage and delete old Axolotl states from the database.
* Extract database configuration into a separate DB config file  
  and abstract more from the actual DB being used (within the code)
* Make the API a shiny RESTful API where POST posts a  
  Prekey to the server, PUT is used for key exchange, etc. (which method
  to use for encrypted messages to the backend? GET?)
* Take care of checking signatures on Prekeys, if we deem that necessary.

