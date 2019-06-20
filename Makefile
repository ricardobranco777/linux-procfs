test:
	@flake8 && \
	pylint $$(find * -name \*.py)
