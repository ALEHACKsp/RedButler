#include <ntddk.h>

#include "Logging.h"
#include "RedDriver.h"
#include "PsMonitor.h"
#include "DeviceAPI.h"
#include "Device.h"

BOOLEAN					g_deviceInitialized = FALSE;
PDEVICE_OBJECT			g_deviceObject = NULL;

// ====================================================================

NTSTATUS IOChangeProcessProtection(PBUT_PROCESS_STATE_PACKET pPacket, SIZE_T szSize) {
	if (szSize < sizeof(BUT_PROCESS_STATE_PACKET)) {
		return STATUS_INVALID_PARAMETER;
	}

	return SetProcessProtection((HANDLE)pPacket->dwProcessId, pPacket->bProtected);
}

NTSTATUS IOChangeProcessExclusion(PBUT_PROCESS_STATE_PACKET pPacket, SIZE_T szSize) {
	if (szSize < sizeof(BUT_PROCESS_STATE_PACKET)) {
		return STATUS_INVALID_PARAMETER;
	}

	return SetProcessExclusion((HANDLE)pPacket->dwProcessId, pPacket->bExcluded);
}

NTSTATUS IOClearProcessAttributes(PBUT_PROCESS_STATE_PACKET pPacket, SIZE_T szSize) {
	if (szSize < sizeof(BUT_PROCESS_STATE_PACKET)) {
		return STATUS_INVALID_PARAMETER;
	}

	return ClearProcessAttributes((HANDLE)pPacket->dwProcessId);
}

// ====================================================================

NTSTATUS IRPDeviceCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS IRPDeviceClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS IRPIoControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);

	PIO_STACK_LOCATION pStack;
	NTSTATUS ntStatus;
	DWORD32 dwIoctl;
	PVOID pInputBuffer, pOutputBuffer, pOutputData;
	SIZE_T szInputBufferSize, szOutputBufferSize,
		szOutputBufferMaxSize, szOutputDataSize, szOutputDataMaxSize;
	BUT_STATUS_PACKET statusPacket;

	ntStatus = STATUS_SUCCESS;
	pStack = IoGetCurrentIrpStackLocation(pIrp);
	dwIoctl = pStack->Parameters.DeviceIoControl.IoControlCode;

	pInputBuffer = pOutputBuffer = pIrp->AssociatedIrp.SystemBuffer;
	szInputBufferSize = pStack->Parameters.DeviceIoControl.InputBufferLength;
	szOutputBufferMaxSize = pStack->Parameters.DeviceIoControl.OutputBufferLength;
	szOutputBufferSize = 0;
	szOutputDataSize = 0;

	// Prepare an additional buffer for output data 
	pOutputData = (PVOID)((UINT_PTR)pOutputBuffer + sizeof(BUT_STATUS_PACKET));
	szOutputDataMaxSize = szOutputBufferMaxSize - sizeof(BUT_STATUS_PACKET);

	RtlZeroMemory(&statusPacket, sizeof(BUT_STATUS_PACKET));

	if (szOutputBufferMaxSize < sizeof(BUT_STATUS_PACKET)) {
		ntStatus = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	switch (dwIoctl) {
		case BUT_IOCTL_GET_DRIVER_STATE: {
			statusPacket.ntStatus = STATUS_SUCCESS;
			statusPacket.info.bState = IsDriverEnabled();
			break;
		}

		case BUT_IOCTL_SET_DRIVER_STATE: {
			statusPacket.ntStatus = STATUS_SUCCESS;
			ChangeDriverState(*(PBOOLEAN)pInputBuffer);
			break;
		}

		case BUT_IOCTL_CHANGE_PROCESS_PROTECTION: {
			statusPacket.ntStatus = IOChangeProcessProtection((PBUT_PROCESS_STATE_PACKET)pInputBuffer,
				szInputBufferSize);
			break;
		}

		case BUT_IOCTL_CHANGE_PROCESS_EXCLUSION: {
			statusPacket.ntStatus = IOChangeProcessExclusion((PBUT_PROCESS_STATE_PACKET)pInputBuffer,
				szInputBufferSize);
			break;
		}

		case BUT_IOCTL_CLEAR_PROCESS_ATTRIBUTES: {
			statusPacket.ntStatus = IOClearProcessAttributes((PBUT_PROCESS_STATE_PACKET)pInputBuffer,
				szInputBufferSize);
			break;
		}

		default: {
			LogWarning("Unknown IOCTL code %08x.", dwIoctl);
			ntStatus = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}

cleanup:
	// If there's additional data
	if (NT_SUCCESS(ntStatus) && szOutputDataSize > 0) {

		// That's a stack corruption!
		if (szOutputDataSize > szOutputDataMaxSize) {
			LogWarning("An internal error occurred, looks like a stack corruption!");

			szOutputDataSize = szOutputDataMaxSize;
			statusPacket.ntStatus = STATUS_PARTIAL_COPY;
		}

		statusPacket.szAdditionalDataSize = szOutputDataSize;
	}

	// Copy the statusPacket to output buffer
	if (NT_SUCCESS(ntStatus)) {
		szOutputBufferSize = sizeof(BUT_STATUS_PACKET);
		RtlCopyMemory(pOutputBuffer, &statusPacket, sizeof(BUT_STATUS_PACKET));
	}

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = szOutputBufferSize;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// ====================================================================

NTSTATUS InitializeDevice(PDRIVER_OBJECT pDriverObject) {
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING(DOS_DEVICES_LINK_NAME);
	PDEVICE_OBJECT deviceObject = NULL;

	status = IoCreateDevice(pDriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status)) {
		LogError("Device creation failed with code %08x.", status);
		return status;
	}

	status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(deviceObject);
		LogError("Symbolic link creation failed with code %08x.", status);
		return status;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = IRPDeviceCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = IRPDeviceClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRPIoControl;
	g_deviceObject = deviceObject;
	g_deviceInitialized = TRUE;

	LogTrace("Initialization completed.");
	return status;
}

NTSTATUS DestroyDevice() {
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING(DOS_DEVICES_LINK_NAME);

	if (!g_deviceInitialized)
		return STATUS_NOT_FOUND;

	status = IoDeleteSymbolicLink(&dosDeviceName);
	if (!NT_SUCCESS(status)) {
		LogWarning("Symbolic link deletion failed with code %08x.", status);
	}

	IoDeleteDevice(g_deviceObject);

	g_deviceInitialized = FALSE;

	LogTrace("Destruction completed.");
	return status;
}