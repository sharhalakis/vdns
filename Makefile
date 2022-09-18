MYPY = mypy
FLAKE8=flake8

all: lint mypy tests

check: mypy lint tests

tests:
	@echo
	@echo Running tests...
	PYTHONPATH=src/ pytest-3

lint: mypy pep8 pylint
	@echo
	@echo Checking source code...

mypy:
	@echo
	@echo Checking types...
	PYTHONPATH=src/ $(MYPY) src/vdns
	PYTHONPATH=src/ $(MYPY) src/bin

pylint: 
	pylint src/vdns

pep8:
	$(FLAKE8) src/vdns
	$(FLAKE8) src/bin
