// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package vnet

import (
	"context"
	"io"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/gravitational/teleport/api"
	"github.com/gravitational/teleport/api/utils/grpc/interceptors"
	vnetv1 "github.com/gravitational/teleport/gen/proto/go/teleport/lib/vnet/v1"
)

type AdminProcessConfig struct {
	// UserProcessServiceAddr is the address of the gRPC service the user
	// process provides to the admin service.
	UserProcessServiceAddr string

	// TODO(nklaassen): delete these, the admin process will decide them, they
	// don't need to be passed from the user process. Keeping them until I
	// remove the references from osconfig.go.
	IPv6Prefix string
	DNSAddr    string
	HomePath   string
}

func (c *AdminProcessConfig) CheckAndSetDefaults() error {
	if c.UserProcessServiceAddr == "" {
		return trace.BadParameter("missing user process service addr")
	}
	return nil
}

// RunAdminProcess must run as administrator. It creates and sets up a TUN
// device and runs the VNet networking stack.
//
// It also handles host OS configuration, OS configuration is updated every [osConfigurationInterval].
//
// The admin process will stay running until the socket at config.socketPath is
// deleted or until encountering an unrecoverable error.
func RunAdminProcess(ctx context.Context, cfg AdminProcessConfig) error {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err, "checking admin process config")
	}
	log.InfoContext(ctx, "Running VNet admin process", "cfg", cfg)
	device, err := tun.CreateTUN("TeleportVNet", mtu)
	if err != nil {
		return trace.Wrap(err, "creating TUN device")
	}
	defer device.Close()
	tunName, err := device.Name()
	if err != nil {
		return trace.Wrap(err, "getting TUN device name")
	}
	log.InfoContext(ctx, "Created TUN interface", "tun", tunName)

	clt, err := newUserProcessClient(ctx, cfg.UserProcessServiceAddr)
	if err != nil {
		return trace.Wrap(err, "creating user process client")
	}
	defer clt.Close()

	if err := authenticateUserProcess(ctx, clt); err != nil {
		log.ErrorContext(ctx, "Failed to authenticate user process", "error", err)
		return trace.Wrap(err, "authenticating user process")
	}

	for {
		select {
		case <-time.After(time.Second):
			resp, err := clt.Ping(ctx, &vnetv1.PingRequest{
				Version: api.Version,
			})
			if err != nil {
				return trace.Wrap(err, "pinging user process")
			}
			if resp.Version != api.Version {
				return trace.BadParameter("version mismatch, user process version is %s, admin process version is %s",
					resp.Version, api.Version)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func authenticateUserProcess(ctx context.Context, clt *userProcessClient) error {
	pipe, err := createNamedPipe(ctx)
	if err != nil {
		return trace.Wrap(err, "creating named pipe")
	}
	defer pipe.Close()
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		_, err := clt.AuthenticateProcess(ctx, &vnetv1.AuthenticateProcessRequest{
			PipePath: pipe.name,
		})
		return trace.Wrap(err, "authenticating user process")
	})
	g.Go(func() error {
		if err := pipe.waitForClient(ctx); err != nil {
			return trace.Wrap(err, "waiting for client to connect to named pipe")
		}
		clientExePath, err := pipe.clientExePath(ctx)
		if err != nil {
			return trace.Wrap(err, "getting pipe client exe path")
		}
		log.DebugContext(ctx, "Got pipe connection from client", "exe", clientExePath)
		thisExePath, err := os.Executable()
		if err != nil {
			return trace.Wrap(err, "getting executable path for this service")
		}
		if thisExePath != clientExePath {
			return trace.AccessDenied("user process is not running the same executable as this service, user process exe: %s, this process exe: %s",
				clientExePath, thisExePath)
		}
		return nil
	})
	if err := g.Wait(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

type winpipe struct {
	pipeHandle  windows.Handle
	eventHandle windows.Handle
	name        string
}

func createNamedPipe(ctx context.Context) (*winpipe, error) {
	pipeName := `\\.\pipe\` + uuid.NewString()
	pipePath, err := syscall.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, trace.Wrap(err, "converting string to UTF16")
	}
	// This allows pipe access to everyone
	// TODO(nklaassen): restrict access to only the calling user.
	sddl := "D:P(A;;GA;;;WD)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, trace.Wrap(err, "creating security descriptor from string")
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}
	pipeHandle, err := windows.CreateNamedPipe(
		pipePath,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		1024,
		1024,
		0,
		&sa,
	)
	if err != nil {
		return nil, trace.Wrap(err, "creating named pipe")
	}
	log.DebugContext(ctx, "Created named pipe", "name", pipeName)
	eventHandle, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, trace.Wrap(err, "creating Windows event handle")
	}
	overlapped := &windows.Overlapped{HEvent: eventHandle}
	if err := windows.ConnectNamedPipe(pipeHandle, overlapped); err != nil && err != windows.ERROR_IO_PENDING {
		return nil, trace.Wrap(err, "connecting to named pipe")
	}
	return &winpipe{
		pipeHandle:  pipeHandle,
		eventHandle: overlapped.HEvent,
		name:        pipeName,
	}, nil
}

func (p *winpipe) waitForClient(ctx context.Context) error {
	evt, err := windows.WaitForSingleObject(p.eventHandle, 500 /*milliseconds*/)
	if err != nil {
		return trace.Wrap(err, "waiting for connection on named pipe")
	}
	if evt != windows.WAIT_OBJECT_0 {
		return trace.Errorf("failed to wait for connection on named pipe, error code: %d", evt)
	}
	return nil
}

func (p *winpipe) clientExePath(ctx context.Context) (string, error) {
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(p.pipeHandle, &pid); err != nil {
		return "", trace.Wrap(err, "getting named pipe client process ID")
	}
	processHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", trace.Wrap(err, "opening client process")
	}
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(processHandle, 0, &buf[0], &size); err != nil {
		return "", trace.Wrap(err, "querying pipe client process image name")
	}
	return windows.UTF16PtrToString(&buf[0]), nil
}

func (p *winpipe) Close() error {
	return trace.NewAggregate(
		trace.Wrap(windows.CloseHandle(p.pipeHandle), "closing pipe handle"),
		trace.Wrap(windows.CloseHandle(p.eventHandle), "closing pipe event handle"),
	)
}

type userProcessClient struct {
	vnetv1.VnetUserProcessServiceClient
	closer io.Closer
}

func newUserProcessClient(ctx context.Context, addr string) (*userProcessClient, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(interceptors.GRPCClientUnaryErrorInterceptor),
		grpc.WithStreamInterceptor(interceptors.GRPCClientStreamErrorInterceptor),
	)
	if err != nil {
		return nil, trace.Wrap(err, "creating user process gRPC client")
	}
	return &userProcessClient{
		VnetUserProcessServiceClient: vnetv1.NewVnetUserProcessServiceClient(conn),
		closer:                       conn,
	}, nil
}

func (c *userProcessClient) Close() error {
	return trace.Wrap(c.closer.Close())
}

var (
	// Satisfy unused linter.
	// TODO(nklaassen): run os configuration loop in admin process.
	_ = osConfigurationLoop
)
