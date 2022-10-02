MYPY = mypy
FLAKE8=flake8

lint: mypy pep8 pylint
	@echo
	@echo Checking source code...

mypy:
	@echo
	@echo Checking types...
	PYTHONPATH=src $(MYPY) src/

pylint:
	pylint src/

pep8:
	$(FLAKE8) src/

tests:
	@echo
	@echo Running tests...
	PYTHONPATH=src/ pytest-3


