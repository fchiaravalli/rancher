package tokens

import (
	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"

	"fmt"
	"strconv"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

var (
	// properSecret is the backend secret matching the properToken
	properSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
		},
		Data: map[string][]byte{
			"enabled":          []byte("false"),
			"is-login":         []byte("true"),
			"ttl":              []byte("4000"),
			"user-id":          []byte("lkajdlksjlkds"),
			"hash":             []byte("kla9jkdmj"),
			"auth-provider":    []byte("somebody"),
			"last-update-time": []byte("13:00:05"),
			"display-name":     []byte("myself"),
			"login-name":       []byte("hello"),
			"principal-id":     []byte("world"),
			"kube-uid":         []byte("2905498-kafld-lkad"),
		},
	}
	// missing user-id - for list tests
	badSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
		},
		Data: map[string][]byte{
			"enabled":          []byte("false"),
			"is-login":         []byte("true"),
			"ttl":              []byte("4000"),
			"hash":             []byte("kla9jkdmj"),
			"auth-provider":    []byte("somebody"),
			"last-update-time": []byte("13:00:05"),
			"display-name":     []byte("myself"),
			"login-name":       []byte("hello"),
			"principal-id":     []byte("world"),
			"kube-uid":         []byte("2905498-kafld-lkad"),
		},
	}
	// properToken is the token matching what is stored in the properSecret
	properToken = ext.Token{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Token",
			APIVersion: "ext.cattle.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
			UID:  types.UID("2905498-kafld-lkad"),
		},
		Spec: ext.TokenSpec{
			UserID:      "lkajdlksjlkds",
			Description: "",
			ClusterName: "",
			TTL:         4000,
			Enabled:     false,
			IsLogin:     true,
		},
		Status: ext.TokenStatus{
			TokenValue:     "",
			TokenHash:      "kla9jkdmj",
			Expired:        true,
			ExpiresAt:      "0001-01-01T00:00:04Z",
			AuthProvider:   "somebody",
			LastUpdateTime: "13:00:05",
			DisplayName:    "myself",
			LoginName:      "hello",
			PrincipalID:    "world",
		},
	}

	dummyToken = ext.Token{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
		},
	}

	// ttlPlusSecret is the properSecret with extended ttl
	ttlPlusSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
		},
		Data: map[string][]byte{
			"enabled":          []byte("false"),
			"is-login":         []byte("true"),
			"ttl":              []byte("5000"),
			"user-id":          []byte("lkajdlksjlkds"),
			"hash":             []byte("kla9jkdmj"),
			"auth-provider":    []byte("somebody"),
			"last-update-time": []byte("13:00:05"),
			"display-name":     []byte("myself"),
			"login-name":       []byte("hello"),
			"principal-id":     []byte("world"),
			"kube-uid":         []byte("2905498-kafld-lkad"),
		},
	}
	// ttlSubSecret is the properSecret with reduced ttl
	ttlSubSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
		},
		Data: map[string][]byte{
			"enabled":          []byte("false"),
			"is-login":         []byte("true"),
			"ttl":              []byte("3000"),
			"user-id":          []byte("lkajdlksjlkds"),
			"hash":             []byte("kla9jkdmj"),
			"auth-provider":    []byte("somebody"),
			"last-update-time": []byte("13:00:05"),
			"display-name":     []byte("myself"),
			"login-name":       []byte("hello"),
			"principal-id":     []byte("world"),
			"kube-uid":         []byte("2905498-kafld-lkad"),
		},
	}

	someerror                = fmt.Errorf("bogus")
	authProviderMissingError = fmt.Errorf("auth provider missing")
	hashMissingError         = fmt.Errorf("token hash missing")
	kubeIDMissingError       = fmt.Errorf("kube uid missing")
	lastUpdateMissingError   = fmt.Errorf("last update time missing")
	principalIDMissingError  = fmt.Errorf("principal id missing")
	userIDMissingError       = fmt.Errorf("user id missing")

	parseBoolError error
	parseIntError  error
)

func init() {
	_, parseBoolError = strconv.ParseBool("")
	_, parseIntError = strconv.ParseInt("", 10, 64)
}

func Test_SystemTokenStore_List(t *testing.T) {
	tests := []struct {
		name       string              // test name
		user       string              // user making request
		admin      bool                //  user is token admin
		opts       *metav1.ListOptions // list options
		err        error               // expected op result, error
		toks       *ext.TokenList      // expected op result, token list
		storeSetup func(               // configure store backend clients
			secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
			uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
			users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList])
	}{
		{
			name:  "some arbitrary error",
			user:  "",
			admin: true,
			opts:  &metav1.ListOptions{},
			err:   apierrors.NewInternalError(fmt.Errorf("failed to list tokens: %w", someerror)),
			toks:  nil,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					List("cattle-tokens", gomock.Any()).
					Return(nil, someerror).
					AnyTimes()
			},
		},
		{
			name:  "ok, empty",
			user:  "",
			admin: true,
			opts:  &metav1.ListOptions{},
			err:   nil,
			toks:  &ext.TokenList{},
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					List("cattle-tokens", gomock.Any()).
					Return(&corev1.SecretList{}, nil).
					AnyTimes()
			},
		},
		{
			name:  "ok, not empty",
			user:  "",
			admin: true,
			opts:  &metav1.ListOptions{},
			err:   nil,
			toks: &ext.TokenList{
				Items: []ext.Token{
					properToken,
				},
			},
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					List("cattle-tokens", gomock.Any()).
					Return(&corev1.SecretList{
						Items: []corev1.Secret{
							properSecret,
						},
					}, nil).
					AnyTimes()
			},
		},
		{
			name:  "ok, ignore broken secrets",
			user:  "",
			admin: true,
			opts:  &metav1.ListOptions{},
			err:   nil,
			toks: &ext.TokenList{
				Items: []ext.Token{
					properToken,
				},
			},
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					List("cattle-tokens", gomock.Any()).
					Return(&corev1.SecretList{
						Items: []corev1.Secret{
							properSecret,
							badSecret,
						},
					}, nil).
					AnyTimes()
			},
		},
		{
			name:  "ok, non-admin, skip non-owned results",
			user:  "other",
			admin: false,
			opts:  &metav1.ListOptions{},
			err:   nil,
			toks:  &ext.TokenList{},
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					List("cattle-tokens", gomock.Any()).
					Return(&corev1.SecretList{
						Items: []corev1.Secret{
							properSecret,
						},
					}, nil).
					AnyTimes()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// mock clients ...
			secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
			uattrs := fake.NewMockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList](ctrl)
			users := fake.NewMockNonNamespacedControllerInterface[*v3.User, *v3.UserList](ctrl)

			// assemble into a store
			store := NewSystemTokenStore(secrets, uattrs, users)

			// configure store backend per test requirements
			test.storeSetup(secrets, uattrs, users)

			// perform test and validate results
			toks, err := store.list(test.admin, test.user, test.opts)
			if test.err != nil {
				assert.Equal(t, test.err, err)
				assert.Nil(t, toks)
			} else {
				assert.NoError(t, err)
				// Force equality on the fields update changes on semi-unpredictably on us
				// (ExpiresAt, LastUpdateTime). -- Can we do this better ?
				//				tok.Status.LastUpdateTime = test.token.Status.LastUpdateTime
				//				tok.Status.ExpiresAt = test.token.Status.ExpiresAt
				assert.Equal(t, toks, test.toks)
			}
		})
	}
}

func Test_SystemTokenStore_Delete(t *testing.T) {
	tests := []struct {
		name       string                // test name
		token      string                // name of token to delete
		opts       *metav1.DeleteOptions // delete options
		err        error                 // expected op result, error
		storeSetup func(                 // configure store backend clients
			secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
			uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
			users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList])
	}{
		{
			name:  "secret not found is ok",
			token: "bogus",
			opts:  &metav1.DeleteOptions{},
			err:   nil,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Delete("cattle-tokens", "bogus", gomock.Any()).
					Return(apierrors.NewNotFound(schema.GroupResource{}, "")).
					AnyTimes()
			},
		},
		{
			name:  "secret other error is fail",
			token: "bogus",
			opts:  &metav1.DeleteOptions{},
			err:   apierrors.NewInternalError(fmt.Errorf("failed to delete token bogus: %w", someerror)),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Delete("cattle-tokens", "bogus", gomock.Any()).
					Return(someerror).
					AnyTimes()
			},
		},
		{
			name:  "secret deleted is ok",
			token: "bogus",
			opts:  &metav1.DeleteOptions{},
			err:   nil,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Delete("cattle-tokens", "bogus", gomock.Any()).
					Return(nil).
					AnyTimes()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// mock clients ...
			secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
			uattrs := fake.NewMockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList](ctrl)
			users := fake.NewMockNonNamespacedControllerInterface[*v3.User, *v3.UserList](ctrl)

			// assemble into a store
			store := NewSystemTokenStore(secrets, uattrs, users)

			// configure store backend per test requirements
			test.storeSetup(secrets, uattrs, users)

			// perform test and validate results
			err := store.Delete(test.token, test.opts)
			if test.err != nil {
				assert.Equal(t, test.err, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_SystemTokenStore_Update(t *testing.T) {
	tests := []struct {
		name       string                // test name
		admin      bool                  // request is from token-admin user
		token      *ext.Token            // token to update, also the expected result
		opts       *metav1.UpdateOptions // update options
		err        error                 // expected op result, error
		storeSetup func(                 // configure store backend clients
			secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
			uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
			users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList])
	}{
		// The first set of tests is equivalent to Get, as that (has to) happen internally
		// before Update can check for (allowed) differences and performing actual storage.
		{
			name:  "backing secret not found",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(nil, apierrors.NewNotFound(schema.GroupResource{}, "")).
					AnyTimes()
			},
			err: apierrors.NewNotFound(schema.GroupResource{}, ""),
		},
		{
			name:  "some other error",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(nil, someerror).
					AnyTimes()
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to retrieve token %s: %w", "bogus", someerror)),
		},
		{
			name:  "empty secret",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&corev1.Secret{}, nil).
					AnyTimes()
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseBoolError)),
		},
		{
			name:  "part-filled secret (enabled)",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "is-login")
				delete(reduced.Data, "ttl")
				delete(reduced.Data, "user-id")
				delete(reduced.Data, "hash")
				delete(reduced.Data, "auth-provider")
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseBoolError)),
		},
		{
			name:  "part-filled secret (enabled, is-login)",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "ttl")
				delete(reduced.Data, "user-id")
				delete(reduced.Data, "hash")
				delete(reduced.Data, "auth-provider")
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseIntError)),
		},
		{
			name:  "part-filled secret (enabled, is-login, ttl)",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "user-id")
				delete(reduced.Data, "hash")
				delete(reduced.Data, "auth-provider")
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", userIDMissingError)),
		},
		{
			name:  "part-filled secret (enabled, is-login, ttl, user id)",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "hash")
				delete(reduced.Data, "auth-provider")
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", hashMissingError)),
		},
		{
			name:  "part-filled secret (enabled, is-login, ttl, user id, hash)",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "auth-provider")
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", authProviderMissingError)),
		},
		{
			name:  "part-filled secret (enabled, is-login, ttl, user id, hash, auth provider)",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", lastUpdateMissingError)),
		},
		{
			name:  "part-filled secret (enabled, is-login, ttl, user id, hash, auth provider, last update)",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", principalIDMissingError)),
		},
		{
			name:  "part-filled secret (enabled, is-login, ttl, user id, hash, auth provider, last update, principal id)",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", kubeIDMissingError)),
		},
		// Second set of tests, compare inbound token against stored token, and reject forbidden changes
		{
			name:  "reject user id change",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.UserID = "dummy"
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil).
					AnyTimes()
			},
			err: apierrors.NewBadRequest("rejecting change of token bogus: forbidden to edit user id"),
		},
		{
			name:  "reject cluster name change",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.ClusterName = "a-cluster"
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil).
					AnyTimes()
			},
			err: apierrors.NewBadRequest("rejecting change of token bogus: forbidden to edit cluster name"),
		},
		{
			name:  "reject login flag change",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.IsLogin = false
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil).
					AnyTimes()
			},
			err: apierrors.NewBadRequest("rejecting change of token bogus: forbidden to edit flag isLogin"),
		},
		// Third set, accepted changes and other errors
		{
			name:  "accept ttl extension (admin op)",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 5000
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)

				// Update: Return changed stored token
				secrets.EXPECT().
					Update(gomock.Any()).
					Return(&ttlPlusSecret, nil)
			},
			err: nil,
		},
		{
			name:  "accept ttl reduction (non-admin op)",
			admin: false,
			opts:  &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 3000
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)

				// Update: Return changed stored token
				secrets.EXPECT().
					Update(gomock.Any()).
					Return(&ttlSubSecret, nil)
			},
			err: nil,
		},
		{
			name:  "reject ttl extension (non-admin op)",
			admin: false,
			opts:  &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 5000
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)
			},
			err: apierrors.NewBadRequest("rejecting change of token bogus: forbidden to extend time-to-live"),
		},
		{
			name:  "fail to save changes",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 2000
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)

				// Update: Fail
				secrets.EXPECT().
					Update(gomock.Any()).
					Return(nil, someerror)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to update token bogus: %w", someerror)),
		},
		{
			name:  "read back broken data after update",
			admin: true,
			opts:  &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 2000
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "user-id")

				// Update: Return broken data (piece missing)
				secrets.EXPECT().
					Update(gomock.Any()).
					Return(reduced, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to regenerate token bogus: %w", userIDMissingError)),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// mock clients ...
			secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
			uattrs := fake.NewMockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList](ctrl)
			users := fake.NewMockNonNamespacedControllerInterface[*v3.User, *v3.UserList](ctrl)

			// assemble into a store
			store := NewSystemTokenStore(secrets, uattrs, users)

			// configure store backend per test requirements
			test.storeSetup(secrets, uattrs, users)

			// perform test and validate results
			tok, err := store.update(test.admin, test.token, test.opts)
			if test.err != nil {
				assert.Equal(t, test.err, err)
				assert.Nil(t, tok)
			} else {
				assert.NoError(t, err)

				// Force equality on the fields update changes on semi-unpredictably on us
				// (ExpiresAt, LastUpdateTime). -- Can we do this better ?
				tok.Status.LastUpdateTime = test.token.Status.LastUpdateTime
				tok.Status.ExpiresAt = test.token.Status.ExpiresAt

				assert.Equal(t, tok, test.token)
			}
		})
	}
}

func Test_SystemTokenStore_Get(t *testing.T) {
	tests := []struct {
		name       string             // test name
		tokname    string             // name of token to retrieve
		opts       *metav1.GetOptions // retrieval options
		err        error              // expected op result, error
		tok        *ext.Token         // expected op result, token
		storeSetup func(              // configure store backend clients
			secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
			uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
			users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList])
	}{
		{
			name: "backing secret not found",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(nil, apierrors.NewNotFound(schema.GroupResource{}, "")).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewNotFound(schema.GroupResource{}, ""),
			tok:     nil,
		},
		{
			name: "some other error",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(nil, someerror).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to retrieve token %s: %w", "bogus", someerror)),
			tok:     nil,
		},
		{
			name: "empty secret",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&corev1.Secret{}, nil).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseBoolError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (enabled)",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "is-login")
				delete(reduced.Data, "ttl")
				delete(reduced.Data, "user-id")
				delete(reduced.Data, "hash")
				delete(reduced.Data, "auth-provider")
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseBoolError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (enabled, is-login)",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "ttl")
				delete(reduced.Data, "user-id")
				delete(reduced.Data, "hash")
				delete(reduced.Data, "auth-provider")
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseIntError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (enabled, is-login, ttl)",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "user-id")
				delete(reduced.Data, "hash")
				delete(reduced.Data, "auth-provider")
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", userIDMissingError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (enabled, is-login, ttl, user id)",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "hash")
				delete(reduced.Data, "auth-provider")
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", hashMissingError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (enabled, is-login, ttl, user id, hash)",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "auth-provider")
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", authProviderMissingError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (enabled, is-login, ttl, user id, hash, auth provider)",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "last-update-time")
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", lastUpdateMissingError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (enabled, is-login, ttl, user id, hash, auth provider, last update)",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "principal-id")
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", principalIDMissingError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (enabled, is-login, ttl, user id, hash, auth provider, last update, principal id)",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", kubeIDMissingError)),
			tok:     nil,
		},
		{
			name: "filled secret",
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil).
					AnyTimes()
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     nil,
			tok: &ext.Token{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Token",
					APIVersion: "ext.cattle.io/v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "bogus",
					UID:  types.UID("2905498-kafld-lkad"),
				},
				Spec: ext.TokenSpec{
					UserID:      "lkajdlksjlkds",
					Description: "",
					ClusterName: "",
					TTL:         4000,
					Enabled:     false,
					IsLogin:     true,
				},
				Status: ext.TokenStatus{
					TokenValue:     "",
					TokenHash:      "kla9jkdmj",
					Expired:        true,
					ExpiresAt:      "0001-01-01T00:00:04Z",
					AuthProvider:   "somebody",
					LastUpdateTime: "13:00:05",
					DisplayName:    "myself",
					LoginName:      "hello",
					PrincipalID:    "world",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// mock clients ...
			secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
			uattrs := fake.NewMockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList](ctrl)
			users := fake.NewMockNonNamespacedControllerInterface[*v3.User, *v3.UserList](ctrl)

			// assemble into a store
			store := NewSystemTokenStore(secrets, uattrs, users)

			// configure store backend per test requirements
			test.storeSetup(secrets, uattrs, users)

			// perform test and validate results
			tok, err := store.Get(test.tokname, test.opts)
			if test.err != nil {
				assert.Equal(t, test.err, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tok, test.tok)
		})
	}
}

// NewSystemTokenStore	core constructor // no admin checks
// NewTokenStore	     		 // admin checks ->

// Create - token store only, not system store - todo expose that for future system-internal token creation

// Update
// 	(TokenStore: fail to check admin
// 		fail to check user full permissions)

// 		fail to set expired
// 			fail to to marshal time

// 	fail on change of TTL extension for non-admin	// can we test `update`, note lower-case

// 	fail on conversion of token to secret
// 		fail to marshal user principal	/json

// 	fail on reading back token (2nd conversion of secret to token)

// 	(TokenStore: fail to check admin)

// List	(TokenStore: fail to check user full permissions)

// Delete (TokenStore)
// 	fail on retrieval of backing secret
// 	fail on conversion of secret to token	(Details s.a.)
