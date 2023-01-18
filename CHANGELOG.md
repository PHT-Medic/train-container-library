# Change Log
All notable changes to this project will be documented in this file.
 
The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [1.2.0] - 2023-01-28

### Added
- Migration to poetry
- Added pre-commit hooks

### Changed
- Updated README.md
- Updated CHANGELOG.md
- Fixed query hashing

### Removed
- Removed setup.py and requirements.txt
- Removed PHT client and rabbitmq client
- Removed unused imports
- 


 
## [0.9.0] - 2021-08-20
 
Test release with internally working version.
 
### Added
- FHIR Client for querying different FHIR servers based on a query.json file
- Documentation for FHIR Client
- Full File system docker image validation comparing train images against public master images
### Changed

### Fixed
Hashing order guarantees the right index of the query.json file in the hash. 