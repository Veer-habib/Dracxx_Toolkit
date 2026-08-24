.PHONY: install test lint run console doctor
install:
	pip install -e .
test:
	pytest -v
lint:
	python -m py_compile $$(find dracxx -name '*.py')
run:
	dracxx-vuln
console:
	dracxx-vuln console
doctor:
	dracxx-vuln doctor
