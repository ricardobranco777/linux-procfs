test:
	@pylint --disable=C0111 $$(find * -name \*.py)
	@flake8 --ignore=E501,W503
	@TZ=UTC LC_ALL=en_US.UTF-8 python3 -m unittest tests/*.py

upload-pypi:
	@python3 setup.py sdist bdist_wheel
	@python3 -m twine upload dist/*

clean:
	@rm -rf dist/ build/ *.egg-info
