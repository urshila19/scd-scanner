# scd-scanner

1. Compliance as Code Framework			
2. Automates compliance checks and validate server configuration against defined security policies like CIS Benchmark			
3. Write tests in human readable Ruby DSL- point to config files, it parses and validate configuration on execution			
4. Supports parsing config files directly,			
5. Formats supported- .conf, .yml, .json, .xml, .ini and direct OS command output			
6. Possible to integrate with CI/CD pipelines, local execution and remote execution over SSH/WinRM			
7. Report Formats- CLI, JSON, HTML, Junit			
8. Highly Customizable, you can modify profiles, add org-specific controls or use existing ones from repo			
9. Use Cases- CIS Benchmark Checks, Infrastructure Security Audits, Cloud Compliance

    docker run --rm -v $(pwd)/controls:/app/controls -v $(pwd)/reports:/app/reports -v $(pwd)/test:/app/test inspectra-webserver

							[Config Files]
							       ↓
						[InSpec Profiles + Controls]
						               ↓
							[inspec exec]
							       ↓
					              [Validation Engine]
							       ↓
					      [Result: PASS/FAIL + HTML Report]		
		
		
		
		
		
		
		
		
		
		
		
		
		
