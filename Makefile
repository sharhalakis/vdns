MYPY=mypy --ignore-missing-imports
PYCODESTYLE=pycodestyle --max-line-length=132 --ignore=E266

all: lint mypy test

check: mypy lint tests

tests:
	@echo
	@echo Running tests...
	PYTHONPATH=src/ pytest-3

mypy:
	@echo
	@echo Checking types...
	PYTHONPATH=src/ $(MYPY) src/vdns
	PYTHONPATH=src/ $(MYPY) src/bin

lint: pep8 pylint
	@echo
	@echo Checking lint...
	
pylint: 
	pylint src/vdns

pep8:
	$(PYCODESTYLE) src/vdns
	$(PYCODESTYLE) src/bin
