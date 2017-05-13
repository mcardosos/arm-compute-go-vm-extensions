# Running this Sample

## Prerequistes
- Have the following installed on your machine before following the rest of the instructions
  - [The Go Programming Language](https://golang.org/) v1.7 or greater
  - [glide](https://github.com/Masterminds/glide) for package management

- Ensure that you have an Azure subscription. You can get started for free here:
[https://azure.microsoft.com/free/](https://azure.microsoft.com/free/)
- Create a Service Principal with a client Secret. For now, you'll need to plug that into source code yourself.

## Steps
1. Ensure that this document, program.go, glide.lock, and glide.yaml were put in a folder matching the following pattern: $GOPATH/src/{package}
2. Update the "const" section at the top of program.go to match the service principal you created during the pre-requisite section of this document. Optionally, you can change the size and location of the VM created.
Note: If this part is not done correctly, the sample will fail saying "Enable failed."
3. From the folder containing program.go, run the command: `glide install`
4. In the same folder, execute the sample by running the following command: `go run program.go -wait`
5. If you used the `-wait` flag, after about 10 minutes, you will prompted with the message "press ENTER to continue...". At that time, you can inspect the VM through the Azure portal and see that the encryption extension has been installed and has started the encryption process.
6. Wait for the sample to complete to ensure that all objects created by the sample are deleted.

# Contributing

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
