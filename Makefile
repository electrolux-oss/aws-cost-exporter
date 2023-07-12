.DEFAULT:
	echo "No rule for target '$@'. Skipped."

clean:
	rm -rf build

build:
	mkdir -p build
	cp -r app/ build/app
	cp *.py package.json requirements.txt build

package:
	docker build . -t ${APP_IMAGE}