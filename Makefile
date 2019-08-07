test:
	@flake8 --ignore=E501,W503 && \
	pylint --disable=C0111 $$(find * -name \*.py)

upload-pypi:
	@python3 setup.py sdist bdist_wheel && \
	python3 -m twine upload dist/*

clean:
	@rm -rf dist/ build/ *.egg-info
