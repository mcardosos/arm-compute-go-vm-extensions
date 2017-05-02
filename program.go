package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/Azure/azure-sdk-for-go/arm/disk"
	"github.com/Azure/azure-sdk-for-go/arm/keyvault"
	"github.com/Azure/azure-sdk-for-go/arm/network"
	"github.com/Azure/azure-sdk-for-go/arm/resources/resources"
	"github.com/Azure/azure-sdk-for-go/arm/storage"
	keys "github.com/Azure/azure-sdk-for-go/dataplane/keyvault"
	"github.com/Azure/go-autorest/autorest"
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
	location = "WESTUS2"
)

func main() {
	var group resources.Group
	var sampleVM compute.VirtualMachine
	var sampleNetwork network.VirtualNetwork
	var sampleStorageAccount storage.Account
	var sampleOSDisk, sampleDataDisk disk.Model
	var sampleVault keyvault.Vault

	var authorizer *azure.Token
	exitStatus := 1
	defer func() {
		os.Exit(exitStatus)
	}()

	debugLog.Println("Using Subscription ID: ", userSubscriptionID)
	debugLog.Println("Using Tenant ID: ", userTenantID)

	// Get authenticated so we can access the subscription used to run this sample.
	if temp, err := authenticate(userClientID, userTenantID); err == nil {
		authorizer = temp
	} else {
		errLog.Printf("could not authenticate. Error: %v", err)
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
			deleter()
		}()
	} else {
		errLog.Printf("could not create resource group. Error: %v", err)
		return
	}

	// Create Pre-requisites for a VM. Because they are independent, we can do so in parallel.
	storageAccountResults, storageAccountErrs := setupStorageAccount(userSubscriptionID, group, authorizer)
	virtualNetworkResults, virtualNetworkErrs := setupVirtualNetwork(userSubscriptionID, group, authorizer)
	vaultResults, vaultErrs := setupKeyVault(userClientID, userSubscriptionID, userTenantID, group, authorizer)

	select {
	case sampleNetwork = <-virtualNetworkResults:
	case err := <-virtualNetworkErrs:
		errLog.Print(err)
		return
	}
	statusLog.Print("Created Virtual Network: ", *sampleNetwork.Name)

	select {
	case sampleStorageAccount = <-storageAccountResults:
	case err := <-storageAccountErrs:
		errLog.Print(err)
		return
	}
	statusLog.Print("Created Storage Account: ", *sampleStorageAccount.Name)

	select {
	case sampleVault = <-vaultResults:
	case err := <-vaultErrs:
		errLog.Print(err)
		return
	}
	statusLog.Print("Created Key Vault: ", *sampleVault.Name)

	osDiskResults, osDiskErrs := setupManagedDisk(userClientID, userSubscriptionID, userTenantID, group, sampleStorageAccount, sampleVault, authorizer)
	dataDiskResults, dataDiskErrs := setupManagedDisk(userClientID, userSubscriptionID, userTenantID, group, sampleStorageAccount, sampleVault, authorizer)

	select {
	case sampleOSDisk = <-osDiskResults:
	case err := <-osDiskErrs:
		errLog.Print(err)
		return
	}
	statusLog.Print("Created OS Disk: ", *sampleOSDisk.Name)

	select {
	case sampleDataDisk = <-dataDiskResults:
	case err := <-dataDiskErrs:
		errLog.Print(err)
		return
	}
	statusLog.Print("Created Data Disk: ", *sampleDataDisk.Name)

	dataDisks := []compute.DataDisk{
		{
			CreateOption: compute.Empty,
			Lun:          to.Int32Ptr(0),
			ManagedDisk: &compute.ManagedDiskParameters{
				ID:                 sampleDataDisk.ID,
				StorageAccountType: compute.StorageAccountTypes(sampleDataDisk.AccountType),
			},
		},
	}

	osDisk := compute.OSDisk{
		CreateOption: compute.Empty,
		ManagedDisk: &compute.ManagedDiskParameters{
			ID:                 sampleDataDisk.ID,
			StorageAccountType: compute.StorageAccountTypes(sampleOSDisk.AccountType),
		},
	}

	// Create an Azure Virtual Machine, on which we'll mount an encrypted data disk.
	if temp, err := setupVirtualMachine(userSubscriptionID, group, sampleStorageAccount, osDisk, dataDisks, (*sampleNetwork.Subnets)[0], authorizer, nil); err == nil {
		sampleVM = temp
		statusLog.Print("Created Virtual Machine: ", *sampleVM.Name)
	} else {
		errLog.Print(err)
		return
	}

	vmClient := compute.NewVirtualMachinesClient(userSubscriptionID.String())
	vmClient.Authorizer = authorizer

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

func setupResourceGroup(subscriptionID uuid.UUID, authorizer autorest.Authorizer) (created resources.Group, deleter func(), err error) {
	resourceClient := resources.NewGroupsClient(subscriptionID.String())
	resourceClient.Authorizer = authorizer

	name := fmt.Sprintf("sample-rg%s", uuid.NewV4().String())

	created, err = resourceClient.CreateOrUpdate(name, resources.Group{
		Location: to.StringPtr(location),
	})

	if err == nil {
		deleter = func() {
			_, err = resourceClient.Delete(*created.Name, nil)
			if err == nil {
				return
			}
		}
	} else {
		deleter = func() {}
	}

	return
}

// setupKeyVault creates a secure location to hold the secrets for encrypting and unencrypting the VM created in this sample's OS and Data disks.
func setupKeyVault(clientID, subscriptionID, tenantID uuid.UUID, group resources.Group, authorizer autorest.Authorizer) (<-chan keyvault.Vault, <-chan error) {
	results, errs := make(chan keyvault.Vault), make(chan error)

	go func() {
		defer close(results)
		defer close(errs)

		client := keyvault.NewVaultsClient(subscriptionID.String())
		client.Authorizer = authorizer

		vaultName := uuid.NewV4().String()
		vaultName = strings.Replace(vaultName, "-", "", -1)
		vaultName = "vault-" + vaultName
		vaultName = vaultName[:24]

		created, err := client.CreateOrUpdate(*group.Name, vaultName, keyvault.VaultCreateOrUpdateParameters{
			Location: group.Location,
			Properties: &keyvault.VaultProperties{
				AccessPolicies: &[]keyvault.AccessPolicyEntry{
					{
						ObjectID: to.StringPtr(clientID.String()),
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

func setupEncryptionKey(clientID, tenantID uuid.UUID, authorizer azure.Token, vault keyvault.Vault) (key keys.KeyBundle, err error) {
	var oAuthConfig *azure.OAuthConfig
	var spt *azure.ServicePrincipalToken

	oAuthConfig, err = environment.OAuthConfigForTenant(tenantID.String())
	if err != nil {
		return
	}

	spt, err = azure.NewServicePrincipalTokenFromManualToken(*oAuthConfig, clientID.String(), environment.KeyVaultEndpoint, authorizer)
	if err != nil {
		return
	}

	client := keys.New()
	client.Authorizer = spt

	keyName := "key-" + uuid.NewV4().String()

	key, err = client.CreateKey(fmt.Sprintf("https://%s.vault.azure.net", *vault.Name), keyName, keys.KeyCreateParameters{
		KeyAttributes: &keys.KeyAttributes{
			Enabled: to.BoolPtr(true),
		},
		KeySize: to.Int32Ptr(1024),
		KeyOps: &[]keys.JSONWebKeyOperation{
			keys.Encrypt,
			keys.Decrypt,
		},
		Kty: keys.RSA,
	})

	statusLog.Print("Encryption key created: ", keyName)

	return
}

func setupManagedDisk(clientID, subscriptionID, tenantID uuid.UUID, group resources.Group, account storage.Account, vault keyvault.Vault, authorizer *azure.Token) (<-chan disk.Model, <-chan error) {
	results, errs := make(chan disk.Model), make(chan error)

	go func() {
		var key keys.KeyBundle
		var err error

		diskClient := disk.NewDisksClient(subscriptionID.String())
		diskClient.Authorizer = authorizer

		diskName := "disk-" + uuid.NewV4().String()

		key, err = setupEncryptionKey(clientID, tenantID, *authorizer, vault)
		if err != nil {
			return
		}

		keyURL, err := key.Location()
		if err != nil {
			errs <- err
			return
		}

		_, err = diskClient.CreateOrUpdate(*group.Name, diskName, disk.Model{
			Location: group.Location,
			Properties: &disk.Properties{
				CreationData: &disk.CreationData{
					CreateOption: disk.Empty,
				},
				DiskSizeGB: to.Int32Ptr(64),
				EncryptionSettings: &disk.EncryptionSettings{
					Enabled: to.BoolPtr(true),
					KeyEncryptionKey: &disk.KeyVaultAndKeyReference{
						KeyURL: to.StringPtr(keyURL.String()),
						SourceVault: &disk.SourceVault{
							ID: vault.ID,
						},
					},
				},
			},
		}, nil)
		if err != nil {
			errs <- err
			return
		}

		created, err := diskClient.Get(*group.Name, diskName)
		results <- created
	}()

	return results, errs
}

func setupVirtualMachine(subscriptionID uuid.UUID, resourceGroup resources.Group, storageAccount storage.Account, osDisk compute.OSDisk, dataDisks []compute.DataDisk, subnet network.Subnet, authorizer autorest.Authorizer, cancel <-chan struct{}) (created compute.VirtualMachine, err error) {
	var networkCard network.Interface

	client := compute.NewVirtualMachinesClient(subscriptionID.String())
	client.Authorizer = authorizer

	vmName := fmt.Sprintf("sample-vm%s", uuid.NewV4().String())
	debugLog.Print("VM Name: ", vmName)

	networkCard, err = setupNetworkInterface(subscriptionID, resourceGroup, subnet, network.SubResource{ID: to.StringPtr(vmName)}, authorizer)
	if err != nil {
		return
	}

	debugLog.Print("NIC ID: ", *networkCard.ID)

	if _, err = client.CreateOrUpdate(*resourceGroup.Name, vmName, compute.VirtualMachine{
		Location: resourceGroup.Location,
		VirtualMachineProperties: &compute.VirtualMachineProperties{
			HardwareProfile: &compute.HardwareProfile{
				VMSize: compute.StandardDS1V2,
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
				OsDisk:    &osDisk,
				DataDisks: &dataDisks,
			},
		},
	}, cancel); err == nil {
		created, err = client.Get(*resourceGroup.Name, vmName, compute.InstanceView)
	}

	if err != nil {
		return
	}
	return
}

func setupVirtualNetwork(subscriptionID uuid.UUID, resourceGroup resources.Group, authorizer autorest.Authorizer) (<-chan network.VirtualNetwork, <-chan error) {
	results, errs := make(chan network.VirtualNetwork), make(chan error)

	go func() {
		defer close(errs)
		defer close(results)

		var err error

		networkClient := network.NewVirtualNetworksClient(subscriptionID.String())
		networkClient.Authorizer = authorizer

		const networkName = "sampleNetwork"

		_, err = networkClient.CreateOrUpdate(*resourceGroup.Name, networkName, network.VirtualNetwork{
			Location: resourceGroup.Location,
			VirtualNetworkPropertiesFormat: &network.VirtualNetworkPropertiesFormat{
				AddressSpace: &network.AddressSpace{
					AddressPrefixes: &[]string{
						"192.168.0.0/16",
					},
				},
			},
		}, nil)
		if err != nil {
			errs <- err
			return
		}

		subnetClient := network.NewSubnetsClient(subscriptionID.String())
		subnetClient.Authorizer = authorizer

		const subnetName = "sampleSubnet"

		_, err = subnetClient.CreateOrUpdate(*resourceGroup.Name, networkName, "sampleSubnet", network.Subnet{
			SubnetPropertiesFormat: &network.SubnetPropertiesFormat{
				AddressPrefix: to.StringPtr("192.168.1.0/24"),
			},
		}, nil)
		if err != nil {
			errs <- err
			return
		}

		created, err := networkClient.Get(*resourceGroup.Name, networkName, "")
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

	_, err = client.CreateOrUpdate(*resourceGroup.Name, name, network.Interface{
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
	if err != nil {
		return
	}

	created, err = client.Get(*resourceGroup.Name, name, "")
	return
}

func setupNetworkSecurityGroup(subscriptionID, resourceGroupName string, authorizer autorest.Authorizer) (created network.SecurityGroup, err error) {
	client := network.NewSecurityGroupsClient(subscriptionID)
	client.Authorizer = authorizer

	name := "sample-nsg"

	_, err = client.CreateOrUpdate(resourceGroupName, name, network.SecurityGroup{
		Location:                      to.StringPtr(location),
		SecurityGroupPropertiesFormat: &network.SecurityGroupPropertiesFormat{},
	}, nil)
	if err != nil {
		return
	}

	created, err = client.Get(resourceGroupName, name, "")
	return
}

func setupPublicIP(subscriptionID uuid.UUID, group resources.Group, authorizer autorest.Authorizer) (created network.PublicIPAddress, err error) {
	client := network.NewPublicIPAddressesClient(subscriptionID.String())
	client.Authorizer = authorizer

	name := "sample-publicip"

	_, err = client.CreateOrUpdate(*group.Name, name, network.PublicIPAddress{
		Location: group.Location,
		PublicIPAddressPropertiesFormat: &network.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: network.Static,
		},
	}, nil)
	if err != nil {
		return
	}

	created, err = client.Get(*group.Name, name, "")
	return
}

func setupStorageAccount(subscriptionID uuid.UUID, group resources.Group, authorizer autorest.Authorizer) (<-chan storage.Account, <-chan error) {
	results, errs := make(chan storage.Account), make(chan error)

	go func() {
		defer close(errs)
		defer close(results)

		client := storage.NewAccountsClient(subscriptionID.String())
		client.Authorizer = authorizer

		storageAccountName := "sample"
		storageAccountName = storageAccountName + string([]byte(uuid.NewV4().String())[:8])
		storageAccountName = strings.ToLower(storageAccountName)
		debugLog.Printf("storageAccountName (length: %d): %s", len(storageAccountName), storageAccountName)

		_, err := client.Create(*group.Name, storageAccountName, storage.AccountCreateParameters{
			Location: group.Location,
			Sku: &storage.Sku{
				Name: storage.StandardLRS,
			},
		}, nil)
		if err != nil {
			errs <- err
			return
		}

		result, err := client.GetProperties(*group.Name, storageAccountName)
		if err != nil {
			errs <- err
			return
		}
		results <- result
	}()

	return results, errs
}

// authenticate gets an authorization token to allow clients to access Azure assets.
func authenticate(clientID, tenantID uuid.UUID) (*azure.Token, error) {
	authClient := autorest.NewClientWithUserAgent("github.com/Azure-Samples/arm-compute-go-vm-extensions")
	var deviceCode *azure.DeviceCode
	var token *azure.Token
	var config *azure.OAuthConfig

	if temp, err := environment.OAuthConfigForTenant(tenantID.String()); err == nil {
		config = temp
	} else {
		return nil, err
	}

	debugLog.Print("DeviceCodeEndpoint: ", config.DeviceCodeEndpoint.String())
	if temp, err := azure.InitiateDeviceAuth(&authClient, *config, clientID.String(), environment.ServiceManagementEndpoint); err == nil {
		deviceCode = temp
	} else {
		return nil, err
	}

	if _, err := fmt.Println(*deviceCode.Message); err != nil {
		return nil, err
	}

	if temp, err := azure.WaitForUserCompletion(&authClient, deviceCode); err == nil {
		token = temp
	} else {
		return nil, err
	}

	return token, nil
}
