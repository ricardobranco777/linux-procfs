test:
	@flake8 --ignore=E501,W503 && \
	pylint $$(find * -name \*.py)
