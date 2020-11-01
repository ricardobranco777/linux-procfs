test:
	@pylint restartable _restartable/*.py tests/*.py
	@flake8 restartable _restartable/*.py tests/*.py --ignore=E501,W503
	@TZ=UTC LC_ALL=en_US.UTF-8 python3 -m unittest tests/*.py
	@tests/integration.sh

upload-pypi:
	@python3 setup.py sdist bdist_wheel
	@python3 -m twine upload dist/*

clean:
	@rm -rf dist/ build/ *.egg-info
