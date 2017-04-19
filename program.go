package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/arm/compute"
	"github.com/Azure/azure-sdk-for-go/arm/resources/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/marstr/guid"
)

var (
	userSubscriptionID string
	userTenantID       string
	environment        = azure.PublicCloud
	oAuthConfig        adal.OAuthConfig
)

var (
	errLog    *log.Logger
	statusLog *log.Logger
)

const (
	clientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" // This is the client ID for the Azure CLI. It was chosen for its public well-known status.
)

func main() {
	var group resources.Group

	resourceClient := resources.NewGroupsClient(userSubscriptionID)
	vmClient := compute.NewVirtualMachinesClient(userSubscriptionID)

	if authorizer, err := authenticate(oAuthConfig); err == nil {
		resourceClient.Authorizer = authorizer
		vmClient.Authorizer = authorizer
	} else {
		errLog.Fatalf("could not authenticate. Error: %v", err)
	}

	if tempGroup, err := resourceClient.CreateOrUpdate(getTempResourceGroupName(), resources.Group{}); err == nil {
		group = tempGroup
		defer resourceClient.Delete(*group.Name, nil)
	} else {
		return
	}
}

func init() {
	var badArgs bool

	errLog = log.New(os.Stderr, "[ERROR] ", 0)
	statusLog = log.New(os.Stdout, "[STATUS] ", 0)

	unformattedSubscriptionID := flag.String("subscription", os.Getenv("AZURE_SUBSCRIPTION_ID"), "The subscription that will be targeted when running this sample.")
	unformattedTenantID := flag.String("tenant", os.Getenv("AZURE_TENANT_ID"), "The tenant that hosts the subscription to be used by this sample.")
	flag.Parse()

	ensureGUID := func(name, raw string) string {
		var retval string
		if parsed, err := guid.Parse(raw); err == nil {
			retval = parsed.String()
		} else {
			errLog.Printf("'%s' doesn't look like an Azure %s. This sample expects a uuid.", raw, name)
			badArgs = true
		}
		return retval
	}

	ensureGUID("Subscription ID", *unformattedSubscriptionID)
	ensureGUID("Tenant ID", *unformattedTenantID)

	if config, err := adal.NewOAuthConfig(environment.ActiveDirectoryEndpoint, userTenantID); err == nil {
		oAuthConfig = *config
	} else {
		errLog.Print("Unable to create OAuthConfig, this may be a problem with the `environment` defined in this sample.")
		badArgs = true
	}

	if badArgs {
		os.Exit(1)
	}
}

func getTempResourceGroupName() string {
	randID := guid.NewGUID()

	return fmt.Sprintf("sample-rg%s", randID.Stringf(guid.FormatN))
}

func authenticate(config adal.OAuthConfig) (autorest.Authorizer, error) {
	authClient := autorest.NewClientWithUserAgent("github.com/Azure-Samples/arm-compute-go-vm-extensions")
	var deviceCode *adal.DeviceCode
	var token *adal.Token

	if temp, err := adal.InitiateDeviceAuth(authClient, config, clientID, environment.ServiceManagementEndpoint); err == nil {
		deviceCode = temp
	} else {
		return nil, err
	}

	if _, err := fmt.Print(*deviceCode.Message); err != nil {
		return nil, err
	}

	if temp, err := adal.WaitForUserCompletion(authClient, deviceCode); err == nil {
		token = temp
	} else {
		return nil, err
	}

	return autorest.NewBearerAuthorizer(token), nil
}
