# Convenience makefile to build the dev env and run common commands
# Based on https://github.com/teamniteo/Makefile

.PHONY: all
all: tests

# Testing and linting targets

.PHONY: check
check:
	@uv run ruff check .
	@uv run ruff format --check .

.PHONY: types
types:
	@uv run ty check --error-on-warning pyramid_jwt2

# anything, in regex-speak
filter = "."

# additional arguments for pytest
full_suite = "false"
ifeq ($(filter),".")
	full_suite = "true"
endif
ifdef path
	full_suite = "false"
endif
args = ""
pytest_args = -k $(filter) $(args)
ifeq ($(args),"")
	pytest_args = -k $(filter)
endif
verbosity = ""
ifeq ($(full_suite),"false")
	verbosity = -vv
endif
full_suite_args = ""
ifeq ($(full_suite),"true")
	full_suite_args = --cov=pyramid_jwt2 --cov-branch --cov-report html --cov-report xml:cov.xml --cov-report term-missing --cov-fail-under=100
endif

.PHONY: unit
unit:
ifndef path
	@uv run pytest tests $(verbosity) $(full_suite_args) $(pytest_args)
else
	@uv run pytest $(path)
endif

.PHONY: tests
tests: check types unit

.PHONY: test
test: tests

# Packaging

.PHONY: build
build:
	@uv build

.PHONY: clean
clean:
	@rm -rf dist/ build/ .coverage cov.xml htmlcov/ .pytest_cache/ .ruff_cache/ *.egg-info/
