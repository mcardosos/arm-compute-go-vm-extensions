package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strings"

	"errors"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/Azure/azure-sdk-for-go/arm/disk"
	"github.com/Azure/azure-sdk-for-go/arm/graphrbac"
	"github.com/Azure/azure-sdk-for-go/arm/keyvault"
	"github.com/Azure/azure-sdk-for-go/arm/network"
	"github.com/Azure/azure-sdk-for-go/arm/resources/resources"
	"github.com/Azure/azure-sdk-for-go/arm/storage"
	keys "github.com/Azure/azure-sdk-for-go/dataplane/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/satori/uuid"
)

var (
	userClientID       uuid.UUID
	userSubscriptionID uuid.UUID
	userTenantID       uuid.UUID
	environment        = azure.PublicCloud
)

var (
	errLog    *log.Logger
	statusLog *log.Logger
	debugLog  *log.Logger
	wait      bool
)

const (
	location                      = "WESTUS2"
	vmProfile                     = compute.StandardDS2V2
	servicePrincipalApplicationID = "INSERT YOUR SERVICE PRINCIPAL APPLICATION ID HERE"

	// You can find this using the azure CLI 2.0 by running the following command after replacing {servicePrincipalApplicationID}:
	// az ad sp show --id {servicePrincipalApplicationID}
	servicePrincipalObjectID = "INSERT YOUR SERVICE PRINCIPAL OBJECT ID HERE"
	servicePrincipalSectet   = "INSERT YOUR SERVICE PRINCIPAL SECRET HERE"
)

func main() {
	var group resources.Group
	var sampleVM compute.VirtualMachine
	var sampleNetwork network.VirtualNetwork
	var sampleStorageAccount storage.Account
	var sampleVault keyvault.Vault
	var token *adal.Token
	var authorizer *autorest.BearerAuthorizer
	var vaultAuthorizer autorest.Authorizer
	var currentUser graphrbac.AADObject
	var err error

	exitStatus := 1
	defer func() {
		os.Exit(exitStatus)
	}()

	debugLog.Println("Using Subscription ID: ", userSubscriptionID)
	debugLog.Println("Using Tenant ID: ", userTenantID)

	// Get authenticated so we can access the subscription used to run this sample.
	if temp, err := authenticate(userClientID, userTenantID); err == nil {
		token = temp
		authorizer = autorest.NewBearerAuthorizer(token)
	} else {
		errLog.Printf("could not authenticate. Error: %v", err)
		return
	}

	// Get AAD ObjectID of the currently authenticated user to give them and only them access to the Key Vault created below.
	var stuff *adal.OAuthConfig
	stuff, err = adal.NewOAuthConfig(environment.ActiveDirectoryEndpoint, userTenantID.String())
	if err != nil {
		return
	}
	var foo *adal.ServicePrincipalToken
	foo, err = adal.NewServicePrincipalTokenFromManualToken(*stuff, userClientID.String(), environment.GraphEndpoint, *token)
	if err != nil {
		return
	}
	err = foo.Refresh()
	if err != nil {
		return
	}

	graphClient := graphrbac.NewObjectsClient(userTenantID.String())
	graphClient.Authorizer = autorest.NewBearerAuthorizer(foo)

	currentUser, err = graphClient.GetCurrentUser()
	if err != nil {
		return
	}
	var userID uuid.UUID
	userID, err = uuid.FromString(*currentUser.ObjectID)
	if err != nil {
		return
	}

	// Create a Resource Group to act as a sandbox for this sample.
	if temp, deleter, err := setupResourceGroup(userSubscriptionID, authorizer); err == nil {
		group = temp
		statusLog.Print("Created Resource Group: ", *group.Name)
		defer func() {
			if wait {
				fmt.Print("press ENTER to continue...")
				fmt.Scanln()
			}
			statusLog.Print("Deleting Resource Group: ", *group.Name)
			if deleted := <-deleter(); deleted != nil {
				errLog.Print(deleted)
			}
		}()
	} else {
		errLog.Printf("could not create resource group. Error: %v", err)
		return
	}

	defer func() {
		if err != nil {
			errLog.Print(err)
		}
	}()

	// Create Pre-requisites for a VM. Because they are independent, we can do so in parallel.
	storageAccountResults, storageAccountErrs := setupStorageAccount(userSubscriptionID, group, authorizer)
	virtualNetworkResults, virtualNetworkErrs := setupVirtualNetwork(userSubscriptionID, group, authorizer)
	vaultResults, vaultErrs := setupKeyVault(userID, userSubscriptionID, userTenantID, group, authorizer)

	sampleNetwork = <-virtualNetworkResults
	if err = <-virtualNetworkErrs; err != nil {
		return
	}
	statusLog.Print("Created Virtual Network: ", *sampleNetwork.Name)

	sampleStorageAccount = <-storageAccountResults
	if err = <-storageAccountErrs; err != nil {
		return
	}
	statusLog.Print("Created Storage Account: ", *sampleStorageAccount.Name)

	sampleVault = <-vaultResults
	if err = <-vaultErrs; err != nil {
		return
	}
	statusLog.Print("Created Key Vault: ", *sampleVault.Name)

	vaultAuthorizer, err = vaultAuthentication(userClientID, userTenantID, *token)

	dataDiskResults, dataDiskErrs := setupManagedDisk(userClientID, userSubscriptionID, userTenantID, group, sampleStorageAccount, sampleVault, authorizer, vaultAuthorizer)

	if err = <-dataDiskErrs; err != nil {
		return
	}

	// Create an Azure Virtual Machine, on which we'll mount an encrypted data disk.
	sampleVM, err = setupVirtualMachine(userClientID, userSubscriptionID, userTenantID, group, sampleStorageAccount, sampleVault, vaultAuthorizer, <-dataDiskResults, (*sampleNetwork.Subnets)[0], authorizer, nil)
	if err != nil {
		return
	}
	statusLog.Print("Created Virtual Machine: ", *sampleVM.Name)

	var kekBundle keys.KeyBundle
	kekBundle, err = setupEncryptionKey(userClientID, userTenantID, vaultAuthorizer, sampleVault)
	if err != nil {
		return
	}
	statusLog.Print("Created KEK: ", *kekBundle.Key.Kid)

	extClient := compute.NewVirtualMachineExtensionsClient(userSubscriptionID.String())
	extClient.Authorizer = authorizer

	asdf := vaultURL(sampleVault)
	debugLog.Print("Vault URL: ", asdf)
	asdf = strings.Trim(asdf, "/")

	_, extErrs := extClient.CreateOrUpdate(*group.Name, *sampleVM.Name, "AzureDiskEncryptionForLinux", compute.VirtualMachineExtension{
		Location: to.StringPtr("WESTUS2"),
		VirtualMachineExtensionProperties: &compute.VirtualMachineExtensionProperties{
			AutoUpgradeMinorVersion: to.BoolPtr(true),
			ProtectedSettings: &map[string]interface{}{
				"AADClientSecret": servicePrincipalSectet, // The Secret that was created for the service principal secret.
				"Passphrase":      "yourPassPhrase",       // This sample uses a simple passphrase, but you should absolutely use something more sophisticated.
			},
			Publisher: to.StringPtr("Microsoft.Azure.Security"),
			Settings: &map[string]interface{}{
				"AADClientID":               servicePrincipalApplicationID,
				"EncryptionOperation":       "EnableEncryption",
				"KeyEncryptionAlgorithm":    "RSA-OAEP",
				"KeyEncryptionKeyAlgorithm": *kekBundle.Key.Kid,
				"KeyVaultURL":               asdf,
				"SequenceVersion":           uuid.NewV4().String(),
				"VolumeType":                "OS",
			},
			Type:               to.StringPtr("AzureDiskEncryptionForLinux"),
			TypeHandlerVersion: to.StringPtr("0.1"),
		},
	}, nil)

	if err = <-extErrs; err != nil {
		return
	}
	statusLog.Print("Disk Encryption Extension Added")

	exitStatus = 0
}

func init() {
	var badArgs bool

	errLog = log.New(os.Stderr, "[ERROR] ", 0)
	statusLog = log.New(os.Stdout, "[STATUS] ", log.Ltime)

	unformattedSubscriptionID := flag.String("subscription", os.Getenv("AZURE_SUBSCRIPTION_ID"), "The subscription that will be targeted when running this sample.")
	unformattedTenantID := flag.String("tenant", os.Getenv("AZURE_TENANT_ID"), "The tenant that hosts the subscription to be used by this sample.")
	printDebug := flag.Bool("debug", false, "Include debug information in the output of this program.")
	flag.BoolVar(&wait, "wait", false, "Use to wait for user acknowledgement before deletion of the created assets.")
	flag.Parse()

	ensureUUID := func(name, raw string) uuid.UUID {
		var retval uuid.UUID
		if parsed, err := uuid.FromString(raw); err == nil {
			retval = parsed
		} else {
			errLog.Printf("'%s' doesn't look like an Azure %s. This sample expects a uuid.", raw, name)
			badArgs = true
		}
		return retval
	}

	userSubscriptionID = ensureUUID("Subscription ID", *unformattedSubscriptionID)
	userTenantID = ensureUUID("Tenant ID", *unformattedTenantID)
	userClientID = ensureUUID("Client ID", "04b07795-8ddb-461a-bbee-02f9e1bf7b46") // This is the client ID for the Azure CLI. It was chosen for its public well-known status.

	var debugWriter io.Writer
	if *printDebug {
		debugWriter = os.Stdout
	} else {
		debugWriter = ioutil.Discard
	}
	debugLog = log.New(debugWriter, "[DEBUG] ", 0)

	if badArgs {
		os.Exit(1)
	}
}

func setupResourceGroup(subscriptionID uuid.UUID, authorizer autorest.Authorizer) (created resources.Group, deleter func() <-chan error, err error) {
	resourceClient := resources.NewGroupsClient(subscriptionID.String())
	resourceClient.Authorizer = authorizer

	name := fmt.Sprintf("sample-rg%s", uuid.NewV4().String())

	created, err = resourceClient.CreateOrUpdate(name, resources.Group{
		Location: to.StringPtr(location),
	})

	if err == nil {
		deleter = func() <-chan error {
			_, result := resourceClient.Delete(*created.Name, nil)
			return result
		}
	} else {
		deleter = func() <-chan error {
			result := make(chan error)
			close(result)
			return result
		}
	}

	return
}

// setupKeyVault creates a secure location to hold the secrets for encrypting and unencrypting the VM created in this sample's OS and Data disks.
func setupKeyVault(userID, subscriptionID, tenantID uuid.UUID, group resources.Group, authorizer autorest.Authorizer) (<-chan keyvault.Vault, <-chan error) {
	results, errs := make(chan keyvault.Vault, 1), make(chan error, 1)

	go func() {
		var err error
		var created keyvault.Vault

		defer close(results)
		defer close(errs)

		client := keyvault.NewVaultsClient(subscriptionID.String())
		client.Authorizer = authorizer

		vaultName := uuid.NewV4().String()
		vaultName = strings.Replace(vaultName, "-", "", -1)
		vaultName = "vault-" + vaultName
		vaultName = vaultName[:24]

		created, err = client.CreateOrUpdate(*group.Name, vaultName, keyvault.VaultCreateOrUpdateParameters{
			Location: group.Location,
			Properties: &keyvault.VaultProperties{
				AccessPolicies: &[]keyvault.AccessPolicyEntry{
					{
						ObjectID: to.StringPtr(userID.String()),
						TenantID: &tenantID,
						Permissions: &keyvault.Permissions{
							Keys:    &[]keyvault.KeyPermissions{keyvault.KeyPermissionsAll},
							Secrets: &[]keyvault.SecretPermissions{keyvault.SecretPermissionsAll},
						},
					},
					{
						ObjectID: to.StringPtr(servicePrincipalObjectID), // The ObjectID of the Service Principal (not the application around it) that will be used programmatically by the extension
						TenantID: &tenantID,
						Permissions: &keyvault.Permissions{
							Keys:    &[]keyvault.KeyPermissions{keyvault.KeyPermissionsAll},
							Secrets: &[]keyvault.SecretPermissions{keyvault.SecretPermissionsAll},
						},
					},
				},
				EnabledForDiskEncryption: to.BoolPtr(true),
				Sku: &keyvault.Sku{
					Family: to.StringPtr("A"),
					Name:   keyvault.Standard,
				},
				TenantID: &tenantID,
			},
		})

		if err != nil {
			errs <- err
			return
		}

		results <- created
	}()

	return results, errs
}

func setupEncryptionKey(clientID, tenantID uuid.UUID, authorizer autorest.Authorizer, vault keyvault.Vault) (key keys.KeyBundle, err error) {
	client := keys.New()
	client.Authorizer = authorizer

	keyName := "key-" + uuid.NewV4().String()

	key, err = client.CreateKey(vaultURL(vault), keyName, keys.KeyCreateParameters{
		KeyAttributes: &keys.KeyAttributes{
			Enabled: to.BoolPtr(true),
		},
		KeySize: to.Int32Ptr(2048), // As of writing this sample, 2048 is the only supported KeySize.
		KeyOps: &[]keys.JSONWebKeyOperation{
			keys.Encrypt,
			keys.Decrypt,
		},
		Kty: keys.RSA,
	})

	return
}

func setupManagedDisk(clientID, subscriptionID, tenantID uuid.UUID, group resources.Group, account storage.Account, vault keyvault.Vault, authorizer, vaultAuthorizer autorest.Authorizer) (<-chan disk.Model, <-chan error) {
	results, errs := make(chan disk.Model, 1), make(chan error, 1)
	go func() {
		var err error
		var created disk.Model
		defer close(results)
		defer close(errs)

		diskClient := disk.NewDisksClient(subscriptionID.String())
		diskClient.Authorizer = authorizer

		diskName := "disk-" + uuid.NewV4().String()

		_, diskErrs := diskClient.CreateOrUpdate(*group.Name, diskName, disk.Model{
			Location: group.Location,
			Properties: &disk.Properties{
				CreationData: &disk.CreationData{
					CreateOption: disk.Empty,
				},
				DiskSizeGB: to.Int32Ptr(64),
			},
		}, nil)
		if err = <-diskErrs; err != nil {
			errs <- err
			return
		}

		created, err = diskClient.Get(*group.Name, diskName)
		if err != nil {
			errs <- err
			return
		}
		results <- created
	}()
	return results, errs
}

func setupVirtualMachine(clientID, subscriptionID, tenantID uuid.UUID, resourceGroup resources.Group, storageAccount storage.Account, vault keyvault.Vault, vaultAuthorizer autorest.Authorizer, dataDisk disk.Model, subnet network.Subnet, authorizer autorest.Authorizer, cancel <-chan struct{}) (created compute.VirtualMachine, err error) {
	var networkCard network.Interface

	client := compute.NewVirtualMachinesClient(subscriptionID.String())
	client.Authorizer = authorizer

	vmName := fmt.Sprintf("sample-vm%s", uuid.NewV4().String())

	networkCard, err = setupNetworkInterface(subscriptionID, resourceGroup, subnet, network.SubResource{ID: to.StringPtr(vmName)}, authorizer)
	if err != nil {
		return
	}

	var storageURI *string
	if storageAccount.PrimaryEndpoints != nil {
		storageURI = (*storageAccount.PrimaryEndpoints).Blob
	} else {
		err = errors.New("No storage endpoint found")
		return
	}
	debugLog.Print("Storage URL: ", *storageAccount.ID)

	_, createErrs := client.CreateOrUpdate(*resourceGroup.Name, vmName, compute.VirtualMachine{
		Location: resourceGroup.Location,
		VirtualMachineProperties: &compute.VirtualMachineProperties{
			DiagnosticsProfile: &compute.DiagnosticsProfile{
				BootDiagnostics: &compute.BootDiagnostics{
					Enabled:    to.BoolPtr(true),
					StorageURI: storageURI,
				},
			},
			HardwareProfile: &compute.HardwareProfile{
				VMSize: vmProfile,
			},
			NetworkProfile: &compute.NetworkProfile{
				NetworkInterfaces: &[]compute.NetworkInterfaceReference{
					{
						ID: networkCard.ID,
						NetworkInterfaceReferenceProperties: &compute.NetworkInterfaceReferenceProperties{
							Primary: to.BoolPtr(true),
						},
					},
				},
			},
			OsProfile: &compute.OSProfile{
				ComputerName:  to.StringPtr(vmName),
				AdminUsername: to.StringPtr("sampleuser"),
				AdminPassword: to.StringPtr("azureRocksWithGo!"),
				LinuxConfiguration: &compute.LinuxConfiguration{
					DisablePasswordAuthentication: to.BoolPtr(false),
				},
			},
			StorageProfile: &compute.StorageProfile{
				ImageReference: &compute.ImageReference{
					Publisher: to.StringPtr("Canonical"),
					Offer:     to.StringPtr("UbuntuServer"),
					Sku:       to.StringPtr("14.04.5-LTS"),
					Version:   to.StringPtr("latest"),
				},
				OsDisk: &compute.OSDisk{
					CreateOption: compute.FromImage,
					DiskSizeGB:   to.Int32Ptr(64),
				},
				DataDisks: &[]compute.DataDisk{},
			},
		},
	}, cancel)
	if err = <-createErrs; err != nil {
		return
	}

	created, err = client.Get(*resourceGroup.Name, vmName, "")
	return
}

func setupServicePrincipal(tenantID uuid.UUID, authToken adal.Token) (<-chan graphrbac.ServicePrincipal, <-chan error, func() error) {
	results, errs := make(chan graphrbac.ServicePrincipal, 1), make(chan error, 1)

	deleter := func() (retval func() error) {
		var spt *adal.ServicePrincipalToken
		var config *adal.OAuthConfig
		var err error
		var result graphrbac.ServicePrincipal

		retval = func() error { return nil }

		defer close(errs)
		defer close(results)

		config, err = adal.NewOAuthConfig(environment.ActiveDirectoryEndpoint, tenantID.String())
		if err != nil {
			errs <- err
			return
		}

		spt, err = adal.NewServicePrincipalTokenFromManualToken(*config, userClientID.String(), environment.GraphEndpoint, authToken)
		if err != nil {
			errs <- err
			return
		}

		client := graphrbac.NewServicePrincipalsClient(tenantID.String())
		client.Authorizer = autorest.NewBearerAuthorizer(spt)

		result, err = client.Create(graphrbac.ServicePrincipalCreateParameters{
			AccountEnabled: to.BoolPtr(false),
		})
		if err != nil {
			errs <- err
			return
		}

		results <- result
		retval = func() (delErr error) {
			_, delErr = client.Delete(*result.ObjectID)
			return
		}
		return
	}()

	return results, errs, deleter
}

func setupVirtualNetwork(subscriptionID uuid.UUID, resourceGroup resources.Group, authorizer autorest.Authorizer) (<-chan network.VirtualNetwork, <-chan error) {
	results, errs := make(chan network.VirtualNetwork, 1), make(chan error, 1)

	go func() {
		defer close(errs)
		defer close(results)

		var tempErrs <-chan error
		var created network.VirtualNetwork
		var err error

		networkClient := network.NewVirtualNetworksClient(subscriptionID.String())
		networkClient.Authorizer = authorizer

		const networkName = "sampleNetwork"

		_, tempErrs = networkClient.CreateOrUpdate(*resourceGroup.Name, networkName, network.VirtualNetwork{
			Location: resourceGroup.Location,
			VirtualNetworkPropertiesFormat: &network.VirtualNetworkPropertiesFormat{
				AddressSpace: &network.AddressSpace{
					AddressPrefixes: &[]string{
						"192.168.0.0/16",
					},
				},
			},
		}, nil)
		if err = <-tempErrs; err != nil {
			errs <- err
			return
		}

		subnetClient := network.NewSubnetsClient(subscriptionID.String())
		subnetClient.Authorizer = authorizer

		const subnetName = "sampleSubnet"

		_, tempErrs = subnetClient.CreateOrUpdate(*resourceGroup.Name, networkName, "sampleSubnet", network.Subnet{
			SubnetPropertiesFormat: &network.SubnetPropertiesFormat{
				AddressPrefix: to.StringPtr("192.168.1.0/24"),
			},
		}, nil)

		if err = <-tempErrs; err != nil {
			errs <- err
			return
		}

		created, err = networkClient.Get(*resourceGroup.Name, networkName, "")
		if err != nil {
			errs <- err
			return
		}

		results <- created
	}()

	return results, errs
}

func setupNetworkInterface(subscriptionID uuid.UUID, resourceGroup resources.Group, subnet network.Subnet, machine network.SubResource, authorizer autorest.Authorizer) (created network.Interface, err error) {
	client := network.NewInterfacesClient(subscriptionID.String())
	client.Authorizer = authorizer

	var ip network.PublicIPAddress

	ip, err = setupPublicIP(subscriptionID, resourceGroup, authorizer)
	if err != nil {
		return
	}

	statusLog.Print("Created Public IP Address: ", *ip.Name, " ", *ip.IPAddress)

	name := "sample-networkInterface"

	_, errs := client.CreateOrUpdate(*resourceGroup.Name, name, network.Interface{
		Location: resourceGroup.Location,
		InterfacePropertiesFormat: &network.InterfacePropertiesFormat{
			IPConfigurations: &[]network.InterfaceIPConfiguration{
				{
					Name: to.StringPtr(fmt.Sprintf("ipConfig-%s", *machine.ID)),
					InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
						PrivateIPAllocationMethod: network.Dynamic,
						Primary:                   to.BoolPtr(true),
						PublicIPAddress:           &ip,
						Subnet:                    &subnet,
					},
				},
			},
		},
	}, nil)
	if err = <-errs; err != nil {
		return
	}

	created, err = client.Get(*resourceGroup.Name, name, "")

	return
}

func setupNetworkSecurityGroup(subscriptionID, resourceGroupName string, authorizer autorest.Authorizer) (created network.SecurityGroup, err error) {
	client := network.NewSecurityGroupsClient(subscriptionID)
	client.Authorizer = authorizer

	name := "sample-nsg"

	results, errs := client.CreateOrUpdate(resourceGroupName, name, network.SecurityGroup{
		Location:                      to.StringPtr(location),
		SecurityGroupPropertiesFormat: &network.SecurityGroupPropertiesFormat{},
	}, nil)
	created, err = <-results, <-errs
	return
}

func setupPublicIP(subscriptionID uuid.UUID, group resources.Group, authorizer autorest.Authorizer) (created network.PublicIPAddress, err error) {
	client := network.NewPublicIPAddressesClient(subscriptionID.String())
	client.Authorizer = authorizer

	name := "sample-publicip"

	_, errs := client.CreateOrUpdate(*group.Name, name, network.PublicIPAddress{
		Location: group.Location,
		PublicIPAddressPropertiesFormat: &network.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: network.Static,
		},
	}, nil)

	if err = <-errs; err != nil {
		return
	}

	created, err = client.Get(*group.Name, name, "")
	return
}

func setupStorageAccount(subscriptionID uuid.UUID, group resources.Group, authorizer autorest.Authorizer) (<-chan storage.Account, <-chan error) {
	client := storage.NewAccountsClient(subscriptionID.String())
	client.Authorizer = authorizer

	storageAccountName := "sample"
	storageAccountName = storageAccountName + string([]byte(uuid.NewV4().String())[:8])
	storageAccountName = strings.ToLower(storageAccountName)

	return client.Create(*group.Name, storageAccountName, storage.AccountCreateParameters{
		Location: group.Location,
		Sku: &storage.Sku{
			Name: storage.StandardLRS,
		},
	}, nil)
}

// authenticate gets an authorization token to allow clients to access Azure assets.
func authenticate(clientID, tenantID uuid.UUID) (*adal.Token, error) {
	authClient := autorest.NewClientWithUserAgent("github.com/Azure-Samples/arm-compute-go-vm-extensions")
	var deviceCode *adal.DeviceCode
	var token *adal.Token
	var config *adal.OAuthConfig

	if temp, err := adal.NewOAuthConfig(environment.ActiveDirectoryEndpoint, tenantID.String()); err == nil {
		config = temp
	} else {
		return nil, err
	}

	if temp, err := adal.InitiateDeviceAuth(&authClient, *config, clientID.String(), environment.ServiceManagementEndpoint); err == nil {
		deviceCode = temp
	} else {
		return nil, err
	}

	if _, err := fmt.Println(*deviceCode.Message); err != nil {
		return nil, err
	}

	if temp, err := adal.WaitForUserCompletion(&authClient, deviceCode); err == nil {
		token = temp
	} else {
		return nil, err
	}

	return token, nil
}

func vaultAuthentication(clientID, tenantID uuid.UUID, token adal.Token) (authorizer autorest.Authorizer, err error) {
	var oAuthConfig *adal.OAuthConfig
	var spt *adal.ServicePrincipalToken

	oAuthConfig, err = adal.NewOAuthConfig(environment.ActiveDirectoryEndpoint, tenantID.String())
	if err != nil {
		return
	}

	var updatedAuthorizeEndpoint *url.URL
	updatedAuthorizeEndpoint, err = url.Parse("https://login.windows.net/" + tenantID.String() + "/oauth2/token")
	oAuthConfig.AuthorizeEndpoint = *updatedAuthorizeEndpoint
	if err != nil {
		return
	}

	spt, err = adal.NewServicePrincipalTokenFromManualToken(*oAuthConfig, clientID.String(), "https://vault.azure.net", token)
	if err != nil {
		return
	}

	err = spt.Refresh()
	if err != nil {
		return
	}

	authorizer = autorest.NewBearerAuthorizer(spt)
	return
}

func vaultURL(vault keyvault.Vault) string {
	return fmt.Sprintf("https://%s.vault.azure.net/", *vault.Name)
}

func formatResponse(resp autorest.Response) string {
	formatted := &bytes.Buffer{}

	fmt.Fprintln(formatted, "Request:")
	fmt.Fprintln(formatted, "\tHeaders:")

	for header, values := range resp.Request.Header {
		fmt.Fprintln(formatted, "\t\t", header)
		for _, val := range values {
			fmt.Fprintln(formatted, "\t\t\t", val)
		}
	}
	reqBody, _ := ioutil.ReadAll(resp.Request.Body)
	fmt.Fprintln(formatted, "\tBody: ", string(reqBody))
	fmt.Fprintln(formatted, "\tRemote Address: ", resp.Request.RemoteAddr)

	fmt.Fprintln(formatted, "Response:")
	fmt.Fprintln(formatted, "\tStatus Code: ", resp.Status)

	fmt.Fprintln(formatted, "\tHeaders:")
	for header, values := range resp.Header {
		fmt.Fprintln(formatted, "\t\t", header)
		for _, val := range values {
			fmt.Fprintln(formatted, "\t\t\t", val)
		}
	}

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintln(formatted, "\tBody: ", string(body))

	return string(formatted.Bytes())
}
