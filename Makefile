FILES = restartable ldpreload */*.py

.PHONY: all
all: flake8 pylint test pytest mypy black

.PHONY: black
flake8:
	@black --check $(FILES)

.PHONY: pylint
pylint:
	@pylint --disable=line-too-long $(FILES)

.PHONY: pytest
pytest:
	@TZ=UTC LC_ALL=en_US.UTF-8 pytest -vv --cov --cov-report term-missing

.PHONY: mypy
mypy:
	@mypy */*.py
	@mypy restartable
	@mypy ldpreload

.PHONY: test
test:
	@TZ=UTC LC_ALL=en_US.UTF-8 python3 -m unittest tests/*.py
	@tests/integration.sh
