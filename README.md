#MobileEdge Server Framework
This is the Node.js implementation of the MobileEdge server framework
developed at e-Mundo as part of a research project. We will make
some documentation about the MobileEdge project available as
soon as possible.

The MobileEdge server framework is still under development and
should __not__ (yet) be used in productive environments. However,
we encourage you to contribute ideas and code if you feel like it!
 
##Dependencies
At the moment, the server framework requires Node.js and
MongoDB to be installed. Tests run fine under Node.js v0.11.13.
We have had some trouble (segmentation faults we found difficult to diagnose) 
on Node.js v0.10.31 on Mac OS X, so we recommend using Node v0.11.13.

Note that we are currently using js-nacl for most of the crypto
functionality, which is something we intend to change in the future. 

##Installation
Installation should be possible just cloning the Github repository
and, in the `MobileEdge-Server/node/` directory, typing 

```npm install```

##Troubleshooting
We have mostly tested installation and running the MobileEdge server
on Ubuntu and Mac OS X systems. If you encounter any problems on
these or different achitectures, let us know. We will do our
best to help identify the problem.

Some problems we had at some point are:

###MongoDB installation fails (GPG-Key trouble)
Use the `mongodb-gpgkey` included in this repository (add it to
APT using `apt-key add mongodb-gpgkey`).

