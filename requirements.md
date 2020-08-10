# Requirements

This document encompasses the requirements of the train library.
The list of requirements is presented in the section `Tabular Requirements`,
the details - if necessary - are accounted for i the section `Detailed Requirements`.

**Note**: The requirements here intersect with the requirements of the Station's RESTful API.


## Tabular Requirements

ID | Name                                                  | Description |
---|-------------------------------------------------------|-------------|
1  | Request for capabilities                              | The Train should be able to check the capabilities of the Station in a single function or method call. Such capabilities could be whether the Station supports GPUs. 
2  | Support for phases                                    | The train might be required to run in multiple phases. A phase is equivalent to one container execution. It should be simple to switch the business logic of the train depending on the phase 
3  | Train requests resources from the Station             | If the Train needs to enter a second phase (because it requires a GPU, the train needs to communicate this to the Station).
4  | FHIR Search client                                    | The library should include a Python FHIR search client such that the explicit use of the `requests` package is avoided.
5  | File system persistence                               | The library should offer functions for persisting models in a consistent way.
6  | Avoid the need for using primitives like `os.environ` | The train business code should not have the need to import `os`, `requests`, `pickle` at all.


## Detailed Requirements.

### 1.
A list of potential capabilities is as follows:
 * The list of devices (like cuda devices that the Station supports).
 * The list of datasets that the Station supports. We can assume that there is a vocabulary of dataset entries
   that the Station can refer to. We assume that these datasets have a token-like name (e.g. `MII-NCD` for the national 
   core data set). 
 * The number of (potential) virtual CPUs.
 * The amount of main memory
 * The amount of HDD space.

### 2.
The train might need to adjust the way the container for the execution is created. For instance,
in the first phase the train might be started without GPU support. If the train requests GPUs in
this phase, a second phase might be initiated (the start of the container would then roughly be like:
`docker run --gpu <device>`). A maximum number of phases of 2 might be sufficient.

### 3.
If the Train needs to enter a subsequent phase, the train needs to communicate this to the Station.
The library needs to provide a function for this.

### 4.
Communication with a FHIR Search API will essentially always be necessary, because
the Train needs to determine the patient pseudonyms of the patients that should be
included in the analysis. These pseudonyms can then used to request / access volume
data. The FHIR Search client should have the following properties:
* Client can search `Patient` and `Encounter` Resources.
* Client can search for diagnoses codes across these Resources 

### 5.
The models must be persisted in the file system in an uniform way (like a common prefix).
There are multiple ways to achieve this:
* The train process runs in a chroot environment (this is somehow difficult)
* There are IO functions and the `open` builtin is no longer used directly

