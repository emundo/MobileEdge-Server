mobileedge:

ssl:
	cd ssl ; sh ./create_self_signed_cert.sh ; cd ..
clean:
	rm -rf build
test:
	./node_modules/.bin/mocha --reporter spec
docs:
	./node_modules/.bin/jsdoc -d build/docs -c docs/jsdoc.conf.json
.PHONY: test docs clean ssl
