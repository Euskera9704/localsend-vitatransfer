import 'dart:async';

import 'package:collection/collection.dart';
import 'package:localsend_app/model/persistence/favorite_device.dart';
import 'package:localsend_app/model/state/nearby_devices_state.dart';
import 'package:localsend_app/provider/favorites_provider.dart';
import 'package:localsend_app/provider/logging/discovery_logs_provider.dart';
import 'package:localsend_isolates/isolate.dart';
import 'package:localsend_isolates/model/device.dart';
import 'package:refena_flutter/refena_flutter.dart';
import 'package:localsend_app/pages/receive_page.dart';
import 'package:localsend_app/pages/vitatransfer_progress_page.dart';
import 'package:localsend_app/provider/selection/selected_receiving_files_provider.dart';
import 'package:localsend_app/util/native/platform_check.dart';
import 'package:localsend_app/util/native/tray_helper.dart';
import 'package:window_manager/window_manager.dart';
import 'package:localsend_isolates/model/dto/file_dto.dart';
import 'package:localsend_isolates/model/session_status.dart';
import 'package:mime/mime.dart';
import 'package:routerino/routerino.dart';

/// This provider is responsible for:
/// - Scanning the network for other LocalSend instances
/// - Keeping track of all found devices (they are only stored in RAM)
///
/// Use [scanProvider] to have a high-level API to perform discovery operations.
final nearbyDevicesProvider = ReduxProvider<NearbyDevicesService, NearbyDevicesState>((ref) {
  return NearbyDevicesService(
    isolateController: ref.notifier(parentIsolateProvider),
    favoriteService: ref.notifier(favoritesProvider),
    discoveryLogs: ref.notifier(discoveryLoggerProvider),
  );
});

class NearbyDevicesService extends ReduxNotifier<NearbyDevicesState> {
  final IsolateController _isolateController;
  final FavoritesService _favoriteService;
  final DiscoveryLogger _discoveryLogger;

  static const Duration _vitaTransferTimeout = Duration(seconds: 6);

  final Map<String, Timer> _vitaTransferExpiryTimers = {};

  NearbyDevicesService({
    required IsolateController isolateController,
    required FavoritesService favoriteService,
    required DiscoveryLogger discoveryLogs,
  }) : _discoveryLogger = discoveryLogs,
       _isolateController = isolateController,
       _favoriteService = favoriteService;

  void _refreshVitaTransferExpiry(
    String fingerprint,
  ) {
    /*
     * Cada anuncio nuevo cancela el timeout anterior.
     */
    _vitaTransferExpiryTimers.remove(fingerprint)?.cancel();

    /*
     * Si durante 6 segundos no recibimos otro anuncio,
     * consideramos que VitaTransfer ya no está disponible.
     */
    _vitaTransferExpiryTimers[fingerprint] = Timer(
      _vitaTransferTimeout,
      () {
        _vitaTransferExpiryTimers.remove(fingerprint);

        redux.dispatch(
          RemoveVitaTransferDeviceAction(
            fingerprint,
          ),
        );
      },
    );
  }

  @override
  void dispose() {
    for (final timer in _vitaTransferExpiryTimers.values) {
      timer.cancel();
    }

    _vitaTransferExpiryTimers.clear();

    super.dispose();
  }

  @override
  NearbyDevicesState init() => const NearbyDevicesState(
    runningFavoriteScan: false,
    runningIps: {},
    devices: {},
    signalingDevices: {},
  );
}

/// Starts the discovery (which binds the UDP port) and registers every
/// confirmed device: answered announcements, scan results and devices fed in
/// via [IsolateDiscoveryAddDeviceAction] all arrive on this one stream.
/// This should run forever as long as the app is running.
class StartDiscoveryListener extends AsyncReduxAction<NearbyDevicesService, NearbyDevicesState> {
  @override
  Future<NearbyDevicesState> reduce() async {
    /*
     * Escuchamos primero las ofertas Vita -> PC.
     *
     * Es importante registrar este listener antes
     * de arrancar el discovery normal para no perder
     * una oferta del Stream broadcast.
     */
    final vitaIncomingStream =
        external(
          notifier._isolateController,
        ).dispatchTakeResult(
          IsolateVitaTransferIncomingListenAction(),
        );

    vitaIncomingStream.listen(
      (offer) async {
        notifier._discoveryLogger.addLog(
          '[VitaTransfer/Main] Incoming offer: '
          '${offer.sessionId} | '
          '${offer.senderName} | '
          '${offer.senderHost}',
        );

        /*
        * Convertimos el manifest VitaTransfer
        * al FileDto que ya entiende ReceivePage.
        */
        final files = offer.files.map((file) {
          final mime = lookupMimeType(file.fileName) ?? 'application/octet-stream';

          return FileDto(
            id: file.id,
            fileName: file.fileName,
            size: file.size.toInt(),
            fileType: decodeFromMime(mime),
            hash: null,
            preview: null,
            metadata: null,
          );
        }).toList();

        for (final file in files) {
          notifier._discoveryLogger.addLog(
            '[VitaTransfer/Main]   '
            '${file.fileName} '
            '(${file.size} bytes)',
          );
        }

        /*
        * Representación del remitente para la UI
        * estándar de LocalSend.
        */
        final sender = Device(
          signalingId: null,
          ip: offer.senderHost,
          version: 'VitaTransfer',
          port: 5002,
          https: false,
          fingerprint: offer.senderFingerprint,
          alias: offer.senderName,
          deviceModel: 'PS Vita',
          deviceType: DeviceType.mobile,
          download: false,
          transport: DeviceTransport.vitaTransfer,
          channels: const [],
        );

        /*
        * ReceivePage utiliza este provider para saber
        * qué archivos están seleccionados.
        *
        * De momento quedan seleccionados todos,
        * igual que en LocalSend normal.
        */
        Routerino.context.notifier(selectedReceivingFilesProvider).setFiles(files);

        /*
        * ViewModel VitaTransfer para ReceivePage.
        *
        * Aceptar/Rechazar todavía NO ejecutan
        * comandos del protocolo.
        */

        bool decisionStarted = false;

        Future<void> rejectIncomingOffer() async {
          try {
            await external(
              notifier._isolateController,
            ).dispatchAsync(
              IsolateVitaTransferRejectIncomingAction(
                sessionId: offer.sessionId,
              ),
            );

            notifier._discoveryLogger.addLog(
              '[VitaTransfer/Main] '
              'Incoming session rejected successfully: '
              '${offer.sessionId}',
            );
          } catch (error) {
            notifier._discoveryLogger.addLog(
              '[VitaTransfer/Main] '
              'Reject ERROR for ${offer.sessionId}: '
              '$error',
            );
          }
        }

        Future<void> acceptIncomingOffer() async {
          try {
            final progressStream =
                external(
                  notifier._isolateController,
                ).dispatchTakeResult(
                  IsolateVitaTransferAcceptIncomingWithProgressAction(
                    sessionId: offer.sessionId,
                  ),
                );

            notifier._discoveryLogger.addLog(
              '[VitaTransfer/Main] '
              'Opening receive progress page for '
              '${offer.sessionId}',
            );

            /*
            * Sustituimos ReceivePage por la misma pantalla de
            * progreso que ya usa PC -> Vita.
            *
            * Es importante usar pushReplacement:
            *
            * ReceivePage
            *      ↓
            * VitaTransferProgressPage
            *
            * y no:
            *
            * ReceivePage
            *      ↓
            * push
            *      ↓
            * ProgressPage
            *
            * porque al pulsar "Hecho" volveríamos otra vez
            * a la pantalla Aceptar/Rechazar.
            */
            await Routerino.context.pushReplacement(
              () => VitaTransferProgressPage.receiving(
                      progressStream: progressStream,
                      files: files,

                      onCancel: () async {
                        notifier._discoveryLogger.addLog(
                          '[VitaTransfer/Main] '
                          'CANCEL pressed for ${offer.sessionId}',
                        );

                        await external(
                          notifier._isolateController,
                        ).dispatchAsync(
                          IsolateVitaTransferCancelIncomingTransferAction(
                            sessionId: offer.sessionId,
                          ),
                        );

                        notifier._discoveryLogger.addLog(
                          '[VitaTransfer/Main] '
                          'Incoming transfer cancelled: '
                          '${offer.sessionId}',
                        );
                      },
                    ),
            );
          } catch (error) {
            notifier._discoveryLogger.addLog(
              '[VitaTransfer/Main] '
              'Accept/transfer ERROR for '
              '${offer.sessionId}: $error',
            );
          }
        }

        final receiveProvider = ViewProvider((ref) {
          return ReceivePageVm(
            status: SessionStatus.waiting,
            sender: sender,
            showSenderInfo: true,
            files: files,
            message: null,

            /*
            * Aceptar todavía no inicia la transferencia.
            * Será el siguiente paso después de validar Rechazar.
            */
            onAccept: () {
              if (decisionStarted) {
                return;
              }

              decisionStarted = true;

              notifier._discoveryLogger.addLog(
                '[VitaTransfer/Main] '
                'ACCEPT pressed for ${offer.sessionId}',
              );

              unawaited(
                acceptIncomingOffer(),
              );
            },

            /*
            * ReceivePage puede llamar a onDecline más de una vez:
            * una al pulsar Rechazar y otra al cerrarse la página.
            */
            onDecline: () {
              if (decisionStarted) {
                return;
              }

              decisionStarted = true;

              notifier._discoveryLogger.addLog(
                '[VitaTransfer/Main] '
                'DECLINE pressed for ${offer.sessionId}',
              );

              unawaited(
                rejectIncomingOffer(),
              );
            },

            onClose: () {
              notifier._discoveryLogger.addLog(
                '[VitaTransfer/Main] '
                'CLOSE pressed for ${offer.sessionId}',
              );
            },
          );
        });

        /*
        * Igual que LocalSend normal:
        * si la ventana está minimizada, oculta o sin foco,
        * reclamamos atención antes de mostrar la solicitud.
        */
        if (
          checkPlatformHasTray() &&
          (
            await windowManager.isMinimized() ||
            !(await windowManager.isVisible()) ||
            !(await windowManager.isFocused())
          )
        )
        {
          await showFromTray();
        }

        /*
        * Abrimos la pantalla estándar de recepción.
        */
        Routerino.context.push(
          () => ReceivePage(receiveProvider),
        );
      },
      onError: (Object error) {
        notifier._discoveryLogger.addLog(
          '[VitaTransfer/Main] '
          'Incoming offer stream ERROR: $error',
        );
      },
    );

    /*
     * Discovery normal de LocalSend + VitaTransfer.
     */
    final stream =
        external(
          notifier._isolateController,
        ).dispatchTakeResult(
          IsolateDiscoveryListenAction(),
        );

    await for (final device in stream) {
      await dispatchAsync(
        RegisterDeviceAction(device),
      );

      notifier._discoveryLogger.addLog(
        '[DISCOVER] '
        '${device.alias} '
        '(${device.ip}, '
        'model: ${device.deviceModel})',
      );
    }

    return state;
  }
}

/// Removes all found devices from the state.
class ClearFoundDevicesAction extends ReduxAction<NearbyDevicesService, NearbyDevicesState> {
  @override
  NearbyDevicesState reduce() {
    return state.copyWith(
      devices: {},
    );
  }
}

/// Registers a device in the state.
/// It will override any existing device with the same fingerprint: the
/// incoming device is the merged store state, so it already carries every
/// address the device was confirmed on.
class RegisterDeviceAction extends AsyncReduxAction<NearbyDevicesService, NearbyDevicesState> {
  final Device device;

  RegisterDeviceAction(this.device);

  @override
  bool get trackOrigin => false;

  @override
  Future<NearbyDevicesState> reduce() async {
    assert(device.ip?.isNotEmpty ?? false, 'IP must not be empty');

    final favoriteDevice = notifier._favoriteService.state.firstWhereOrNull((e) => e.fingerprint == device.fingerprint);
    if (favoriteDevice != null && !favoriteDevice.customAlias) {
      // Update existing favorite with new alias
      await external(notifier._favoriteService).dispatchAsync(UpdateFavoriteAction(favoriteDevice.copyWith(alias: device.alias)));
    } else {
      await Future.microtask(() {});
    }

    if (device.transport == DeviceTransport.vitaTransfer) {
      notifier._refreshVitaTransferExpiry(
        device.fingerprint,
      );
    }
    return state.copyWith(
      devices: {...state.devices}..update(device.fingerprint, (_) => device, ifAbsent: () => device),
    );
  }
}

class RemoveVitaTransferDeviceAction extends ReduxAction<NearbyDevicesService, NearbyDevicesState> {
  final String fingerprint;

  RemoveVitaTransferDeviceAction(
    this.fingerprint,
  );

  @override
  bool get trackOrigin => false;

  @override
  NearbyDevicesState reduce() {
    final device = state.devices[fingerprint];

    /*
     * Si ya no existe, no hacemos nada.
     */
    if (device == null) {
      return state;
    }

    /*
     * Protección adicional:
     * esta acción solamente puede eliminar
     * dispositivos VitaTransfer.
     */
    if (device.transport != DeviceTransport.vitaTransfer) {
      return state;
    }

    final devices = Map<String, Device>.from(
      state.devices,
    );

    devices.remove(
      fingerprint,
    );

    return state.copyWith(
      devices: devices,
    );
  }
}

/// Registers a new device found via signaling.
class RegisterSignalingDeviceAction extends ReduxAction<NearbyDevicesService, NearbyDevicesState> {
  final Device device;

  RegisterSignalingDeviceAction(this.device);

  @override
  NearbyDevicesState reduce() {
    final Set<Device> existingDevices = state.signalingDevices[device.fingerprint]?.toSet() ?? {};
    final existingDevice = existingDevices.firstWhereOrNull((e) => e.signalingId == device.signalingId);
    if (existingDevice != null) {
      existingDevices.remove(existingDevice);
    }
    existingDevices.add(device);

    return state.copyWith(
      signalingDevices: {
        ...state.signalingDevices,
        device.fingerprint: existingDevices,
      },
    );
  }
}

class UnregisterSignalingDeviceAction extends ReduxAction<NearbyDevicesService, NearbyDevicesState> {
  final String signalingId;

  UnregisterSignalingDeviceAction(this.signalingId);

  @override
  NearbyDevicesState reduce() {
    return state.copyWith(
      signalingDevices: {
        for (final entry in state.signalingDevices.entries) entry.key: entry.value.where((e) => e.signalingId != signalingId).toSet(),
      },
    );
  }
}

/// It does not really "scan".
/// It just sends an announcement which will cause a response on every other LocalSend member of the network.
class StartMulticastScan extends ReduxAction<NearbyDevicesService, NearbyDevicesState> {
  @override
  NearbyDevicesState reduce() {
    external(notifier._isolateController).dispatch(IsolateDiscoveryAnnouncementAction());
    return state;
  }
}

/// Scans one particular subnet with traditional HTTP/TCP discovery.
/// This method awaits until the scan is finished.
class StartLegacyScan extends AsyncReduxAction<NearbyDevicesService, NearbyDevicesState> {
  final int port;
  final String localIp;
  final bool https;

  StartLegacyScan({
    required this.port,
    required this.localIp,
    required this.https,
  });

  @override
  Future<NearbyDevicesState> reduce() async {
    if (state.runningIps.contains(localIp)) {
      // already running for the same localIp
      await Future.microtask(() {});
      return state;
    }

    dispatch(_SetRunningIpsAction({...state.runningIps, localIp}));

    // The found devices arrive on the [StartDiscoveryListener] stream;
    // this stream only signals when the scan is finished.
    await external(notifier._isolateController)
        .dispatchTakeResult(
          IsolateDiscoverySubnetScanAction(
            networkInterface: localIp,
            port: port,
            https: https,
          ),
        )
        .drain<void>();

    return state.copyWith(
      runningIps: state.runningIps.where((ip) => ip != localIp).toSet(),
    );
  }
}

/// Discovers devices in stages, cheapest first: multicast announcement and
/// favorite probes right away, a subnet scan of [interfaces] only when
/// nothing was confirmed within the grace period.
/// This method awaits until every stage is finished.
class StartStagedScan extends AsyncReduxAction<NearbyDevicesService, NearbyDevicesState> {
  final List<FavoriteDevice> favorites;
  final List<String> interfaces;
  final int port;
  final bool https;
  final Duration grace;

  StartStagedScan({
    required this.favorites,
    required this.interfaces,
    required this.port,
    required this.https,
    required this.grace,
  });

  @override
  Future<NearbyDevicesState> reduce() async {
    dispatch(_SetRunningFavoriteScanAction(true));

    // The found devices arrive on the [StartDiscoveryListener] stream;
    // this stream only signals when every stage has finished.
    await external(notifier._isolateController)
        .dispatchTakeResult(
          IsolateDiscoveryStagedScanAction(
            favorites: favorites.map((e) => (e.ip, e.port)).toList(),
            networkInterfaces: interfaces,
            port: port,
            https: https,
            grace: grace,
          ),
        )
        .drain<void>();

    return state.copyWith(
      runningFavoriteScan: false,
    );
  }
}

class _SetRunningIpsAction extends ReduxAction<NearbyDevicesService, NearbyDevicesState> {
  final Set<String> runningIps;

  _SetRunningIpsAction(this.runningIps);

  @override
  NearbyDevicesState reduce() {
    return state.copyWith(
      runningIps: runningIps,
    );
  }
}

class _SetRunningFavoriteScanAction extends ReduxAction<NearbyDevicesService, NearbyDevicesState> {
  final bool running;

  _SetRunningFavoriteScanAction(this.running);

  @override
  NearbyDevicesState reduce() {
    return state.copyWith(
      runningFavoriteScan: running,
    );
  }
}
