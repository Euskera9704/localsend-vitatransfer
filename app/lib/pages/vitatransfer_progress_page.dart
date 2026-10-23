import 'dart:async';

import 'package:flutter/material.dart';
import 'package:localsend_app/gen/strings.g.dart';
import 'package:localsend_app/model/cross_file.dart';
import 'package:localsend_app/util/ui/nav_bar_padding.dart';
import 'package:localsend_app/widget/custom_progress_bar.dart';
import 'package:localsend_app/widget/dialogs/cancel_session_dialog.dart';
import 'package:localsend_app/widget/file_thumbnail.dart';
import 'package:localsend_isolates/model/dto/file_dto.dart';
import 'package:localsend_isolates/rust/api/vitatransfer.dart';
import 'package:localsend_isolates/util/file_size_helper.dart';
import 'package:routerino/routerino.dart';

const _advancedProgressPanelExtraPadding = 100.0;

class VitaTransferProgressPage extends StatefulWidget {
  /*
   * =========================================================
   * PC -> VITA
   * =========================================================
   */
  final RsVitaTransferSendSession? session;
  final List<CrossFile>? files;

  /*
   * =========================================================
   * VITA -> PC
   * =========================================================
   */
  final Stream<RsVitaTransferReceiveProgress>?
      receiveProgress;

  final List<FileDto>? receiveFiles;

  final Future<void> Function()? onCancelReceive;

  final bool receiving;
  final bool showAppBar;

  /*
   * Constructor original.
   *
   * Lo seguimos utilizando sin cambios para PC -> Vita.
   */
  const VitaTransferProgressPage({
    super.key,
    required RsVitaTransferSendSession session,
    required List<CrossFile> files,
    this.showAppBar = false,
  })  : session = session,
        files = files,
        receiveProgress = null,
        receiveFiles = null,
        onCancelReceive = null,
        receiving = false;

  /*
   * Nuevo modo Vita -> PC.
   */
  const VitaTransferProgressPage.receiving({
    super.key,
    required Stream<RsVitaTransferReceiveProgress>
        progressStream,
    required List<FileDto> files,
    required Future<void> Function()
        onCancel,
    this.showAppBar = false,
  })  : session = null,
        files = null,
        receiveProgress = progressStream,
        receiveFiles = files,
        onCancelReceive = onCancel,
        receiving = true;

  @override
  State<VitaTransferProgressPage> createState() =>
      _VitaTransferProgressPageState();
}

class _VitaTransferProgressPageState
    extends State<VitaTransferProgressPage> {
  StreamSubscription<dynamic>? _subscription;

  late final List<int> _fileBytesSent;
  late final int _totalSize;

  int _totalBytesSent = 0;
  int _currentFileIndex = 0;

  double _megabytesPerSecond = 0.0;

  bool _advanced = false;
  bool _finished = false;
  bool _canceled = false;
  bool _cancelRequested = false;

  String? _error;

  int get _fileCount {
    return widget.receiving
        ? widget.receiveFiles!.length
        : widget.files!.length;
  }


  int _fileSizeAt(
    int index,
  ) {
    return widget.receiving
        ? widget.receiveFiles![index].size
        : widget.files![index].size;
  }


  String _fileNameAt(
    int index,
  ) {
    return widget.receiving
        ? widget.receiveFiles![index].fileName
        : widget.files![index].name;
  }

  @override
  void initState() {
    super.initState();

    _fileBytesSent =
        List<int>.filled(
          _fileCount,
          0,
        );

    _totalSize =
        List<int>.generate(
          _fileCount,
          _fileSizeAt,
        ).fold<int>(
          0,
          (
            previous,
            size,
          ) =>
              previous + size,
        );

    /*
    * =====================================================
    * VITA -> PC
    * =====================================================
    */
    if (widget.receiving) {
      _subscription =
          widget.receiveProgress!.listen(
        _onReceiveProgress,
        onError: _onStreamError,
        onDone: _onReceiveDone,
      );

      return;
    }

    /*
    * =====================================================
    * PC -> VITA
    * =====================================================
    *
    * Comportamiento original.
    */
    _subscription =
        widget.session!
            .sendWithProgress()
            .listen(
              _onProgress,
              onError: _onStreamError,
            );
  }

  void _onProgress(
    RsVitaTransferProgress progress,
  ) {
    if (!mounted) {
      return;
    }

    setState(() {
      /*
       * =====================================================
       * CANCELACIÓN
       * =====================================================
       */

      if (progress.canceled) {
        _canceled = true;
        _finished = true;
        _megabytesPerSecond = 0.0;

        return;
      }

      /*
       * =====================================================
       * ERROR
       * =====================================================
       */

      if (progress.error != null) {
        _error = progress.error;
        _finished = true;
        _megabytesPerSecond = 0.0;

        return;
      }

      /*
       * =====================================================
       * PROGRESO NORMAL
       * =====================================================
       */

      if (progress.fileIndex > 0) {
        final index =
            progress.fileIndex - 1;

        if (index >= 0 &&
            index < _fileCount) {
          /*
           * Si hemos empezado un archivo nuevo,
           * los anteriores ya terminaron.
           */
          for (
            var previous = 0;
            previous < index;
            previous++
          ) {
            _fileBytesSent[previous] =
                _fileSizeAt(previous);
          }

          _currentFileIndex = index;

          final bytes =
              progress.fileBytesSent
                  .toInt();

          _fileBytesSent[index] =
              _clamp(
                bytes,
                0,
                _fileSizeAt(index),
              );
        }
      }

      _totalBytesSent =
          _clamp(
            progress.totalBytesSent
                .toInt(),
            0,
            _totalSize,
          );

      _megabytesPerSecond =
          progress.megabytesPerSecond;

      /*
       * =====================================================
       * FINAL CORRECTO
       * =====================================================
       */

      if (progress.finished) {
        for (
          var index = 0;
          index < _fileCount;
          index++
        ) {
          _fileBytesSent[index] =
              _fileSizeAt(index);
        }

        _totalBytesSent =
            _totalSize;

        _finished = true;
        _megabytesPerSecond = 0.0;
      }
    });
  }

  void _onReceiveProgress(
    RsVitaTransferReceiveProgress progress,
  ) {
    if (!mounted) {
      return;
    }

    setState(() {
      /*
      * fileNumber viene de Rust basado en 1:
      *
      * 1/2 -> índice 0
      * 2/2 -> índice 1
      */
      final index =
          progress.fileNumber - 1;

      if (
        index >= 0 &&
        index < _fileCount
      ) {
        /*
        * Si hemos empezado otro archivo,
        * todos los anteriores ya terminaron.
        */
        for (
          var previous = 0;
          previous < index;
          previous++
        ) {
          _fileBytesSent[previous] =
              _fileSizeAt(previous);
        }

        _currentFileIndex =
            index;

        _fileBytesSent[index] =
            _clamp(
          progress
              .fileBytesReceived
              .toInt(),
          0,
          _fileSizeAt(index),
        );

        /*
        * fileFinished significa que SHA-256
        * de ese archivo ya fue validado.
        */
        if (progress.fileFinished) {
          _fileBytesSent[index] =
              _fileSizeAt(index);
        }
      }

      _totalBytesSent =
          _clamp(
        progress
            .batchBytesReceived
            .toInt(),
        0,
        _totalSize,
      );

      _megabytesPerSecond =
          progress.megabytesPerSecond;
    });
  }

  void _onReceiveDone() {
    if (!mounted) {
      return;
    }

    setState(() {

      if (_cancelRequested) {
        _canceled = true;
        _finished = true;
        _megabytesPerSecond = 0.0;

        return;
      }

      /*
      * Si ya había error, no lo convertimos
      * artificialmente en transferencia correcta.
      */
      if (_error != null) {
        return;
      }

      for (
        var index = 0;
        index < _fileCount;
        index++
      ) {
        _fileBytesSent[index] =
            _fileSizeAt(index);
      }

      _totalBytesSent =
          _totalSize;

      _finished = true;
      _megabytesPerSecond = 0.0;
    });
  }

  void _onStreamError(
    Object error,
  ) {
    if (!mounted) {
      return;
    }

    setState(() {
      _error =
          error.toString();

      _finished = true;
      _megabytesPerSecond = 0.0;
    });
  }

  int _clamp(
    int value,
    int minimum,
    int maximum,
  ) {
    if (value < minimum) {
      return minimum;
    }

    if (value > maximum) {
      return maximum;
    }

    return value;
  }

  double _fileProgress(
    int index,
  ) {
    final size =
        _fileSizeAt(index);

    if (size <= 0) {
      return 0.0;
    }

    return _fileBytesSent[index] /
        size;
  }

  double get _totalProgress {
    if (_totalSize <= 0) {
      return 0.0;
    }

    return _totalBytesSent /
        _totalSize;
  }

  int get _finishedFileCount {
    var count = 0;

    for (
      var index = 0;
      index < _fileCount;
      index++
    ) {
      if (_fileBytesSent[index] >=
              _fileSizeAt(index)) {
        count++;
      }
    }

    return count;
  }

  String get _remainingTime {
    if (_finished ||
        _megabytesPerSecond <= 0.0) {
      return '-';
    }

    final remainingBytes =
        _totalSize -
        _totalBytesSent;

    if (remainingBytes <= 0) {
      return '0:00';
    }

    final bytesPerSecond =
        _megabytesPerSecond *
        1024.0 *
        1024.0;

    if (bytesPerSecond <= 0.0) {
      return '-';
    }

    final seconds =
        (remainingBytes /
                bytesPerSecond)
            .ceil();

    final minutes =
        seconds ~/ 60;

    final remainingSeconds =
        seconds % 60;

    return '$minutes:${remainingSeconds.toString().padLeft(2, '0')}';
  }

  String get _totalTitle {
    if (_canceled) {
      return t
          .progressPage
          .total
          .title
          .canceledSender;
    }

    if (_error != null) {
      return t
          .progressPage
          .total
          .title
          .finishedError;
    }

    if (_finished) {
      return t.general.finished;
    }

    return t
        .progressPage
        .total
        .title
        .sending(
          time: _remainingTime,
        );
  }

  Future<void> _cancel() async {
    if (_finished ||
        _cancelRequested) {
      return;
    }

    final confirmed =
        (await context.pushBottomSheet(
          () =>
              const CancelSessionDialog(),
        )) ==
        true;

    if (!confirmed ||
        !mounted) {
      return;
    }

    setState(() {
      _cancelRequested = true;
    });

    try {
      /*
      * ===============================================
      * VITA -> PC
      * ===============================================
      */
      if (widget.receiving) {
        await widget.onCancelReceive!();

        if (!mounted) {
          return;
        }

        setState(() {
          _canceled = true;
          _finished = true;
          _megabytesPerSecond = 0.0;
        });

        return;
      }

      /*
      * ===============================================
      * PC -> VITA
      * ===============================================
      */
      await widget.session!.cancel();
    } catch (error) {
      if (!mounted) {
        return;
      }

      setState(() {
        _error =
            error.toString();

        _finished = true;
        _megabytesPerSecond = 0.0;
      });
    }
  }

  Future<void> _onClosePressed() async {
    if (!_finished) {
      await _cancel();

      return;
    }

    if (mounted) {
      Navigator.of(context).pop();
    }
  }

  @override
  void dispose() {
    final subscription =
        _subscription;

    if (subscription != null) {
      unawaited(
        subscription.cancel(),
      );
    }

    super.dispose();
  }

  @override
  Widget build(
    BuildContext context,
  ) {
    final title =
        widget.receiving
            ? t.progressPage.titleReceiving
            : t.progressPage.titleSending;

    return PopScope(
      canPop: _finished,

      onPopInvokedWithResult: (
        didPop,
        result,
      ) async {
        if (didPop) {
          return;
        }

        await _cancel();
      },

      child: Scaffold(
        appBar:
            widget.showAppBar
                ? AppBar(
                  title:
                      Text(title),
                )
                : null,

        body: Stack(
          children: [
            /*
             * =================================================
             * LISTA DE ARCHIVOS
             * =================================================
             */

            ListView.builder(
              padding:
                  EdgeInsets.only(
                    top:
                        MediaQuery.of(
                              context,
                            ).padding.top +
                        20,

                    bottom:
                        150 +
                        (_advanced
                            ? _advancedProgressPanelExtraPadding
                            : 0) +
                        getNavBarPadding(
                          context,
                        ),

                    left: 15,
                    right: 30,
                  ),

              itemCount:
                  _fileCount + 2,

              itemBuilder: (
                context,
                index,
              ) {
                /*
                 * TÍTULO
                 */
                if (index == 0) {
                  if (widget.showAppBar) {
                    return const SizedBox.shrink();
                  }

                  return Padding(
                    padding:
                        const EdgeInsets.only(
                          bottom: 5,
                        ),

                    child: Text(
                      title,

                      style:
                          Theme.of(
                                context,
                              )
                              .textTheme
                              .titleLarge,
                    ),
                  );
                }

                /*
                 * ERROR
                 */
                if (index == 1) {
                  if (_error == null) {
                    return const SizedBox.shrink();
                  }

                  return Padding(
                    padding:
                        const EdgeInsets.symmetric(
                          vertical: 10,
                        ),

                    child: SelectableText(
                      _error!,

                      style: TextStyle(
                        color:
                            Theme.of(
                                  context,
                                )
                                .colorScheme
                                .error,
                      ),
                    ),
                  );
                }

                /*
                 * ARCHIVO
                 */
                final fileIndex =
                    index - 2;

                final outgoingFile =
                    widget.receiving
                        ? null
                        : widget.files![fileIndex];

                final incomingFile =
                    widget.receiving
                        ? widget.receiveFiles![fileIndex]
                        : null;

                final fileName =
                    _fileNameAt(fileIndex);

                final fileSize =
                    _fileSizeAt(fileIndex);

                final progress =
                    _fileProgress(
                      fileIndex,
                    );

                final completed =
                    _fileBytesSent[fileIndex] >=
                    fileSize;

                final currentlySending =
                    !_finished &&
                    fileIndex ==
                        _currentFileIndex;

                return Padding(
                  padding:
                      const EdgeInsets.symmetric(
                        vertical: 5,
                      ),

                  child: Row(
                    crossAxisAlignment:
                        CrossAxisAlignment.center,

                    children: [
                      SmartFileThumbnail(
                          bytes:
                              outgoingFile?.thumbnail,

                          asset:
                              outgoingFile?.asset,

                          path:
                              outgoingFile?.path,

                          fileType:
                              widget.receiving
                                  ? incomingFile!.fileType
                                  : outgoingFile!.fileType,
                        ),

                      const SizedBox(
                        width: 10,
                      ),

                      Expanded(
                        child: Column(
                          crossAxisAlignment:
                              CrossAxisAlignment.start,

                          children: [
                            Row(
                              children: [
                                Flexible(
                                  child: Text(
                                    fileName,

                                    style:
                                        const TextStyle(
                                          fontSize: 16,
                                          height: 1,
                                        ),

                                    maxLines: 1,

                                    overflow:
                                        TextOverflow.fade,

                                    softWrap:
                                        false,
                                  ),
                                ),

                                Text(
                                  ' (${fileSize.asReadableFileSize})',

                                  style:
                                      const TextStyle(
                                        fontSize: 16,
                                        height: 1,
                                      ),
                                ),
                              ],
                            ),

                            const SizedBox(
                              height: 5,
                            ),

                            if (currentlySending)
                              Padding(
                                padding:
                                    const EdgeInsets.only(
                                      top: 5,
                                    ),

                                child:
                                    CustomProgressBar(
                                      progress:
                                          progress,
                                    ),
                              )
                            else
                              Text(
                                completed
                                    ? t.general.done
                                    : _canceled
                                    ? t
                                        .progressPage
                                        .total
                                        .title
                                        .canceledSender
                                    : t.general.queue,

                                style:
                                    TextStyle(
                                      color:
                                          Theme.of(
                                                context,
                                              )
                                              .colorScheme
                                              .primary,

                                      height: 1,
                                    ),
                              ),
                          ],
                        ),
                      ),
                    ],
                  ),
                );
              },
            ),

            /*
             * =================================================
             * TARJETA INFERIOR
             * =================================================
             */

            SafeArea(
              child: Align(
                alignment:
                    Alignment.bottomCenter,

                child: Padding(
                  padding:
                      const EdgeInsets.only(
                        left: 10,
                        right: 10,
                        bottom: 10,
                      ),

                  child: Card(
                    child: Padding(
                      padding:
                          const EdgeInsets.only(
                            left: 15,
                            right: 15,
                            bottom: 5,
                            top: 10,
                          ),

                      child: Column(
                        crossAxisAlignment:
                            CrossAxisAlignment.start,

                        mainAxisSize:
                            MainAxisSize.min,

                        children: [
                          Text(
                            _totalTitle,

                            style:
                                const TextStyle(
                                  fontSize: 20,
                                ),
                          ),

                          const SizedBox(
                            height: 5,
                          ),

                          TweenAnimationBuilder<double>(
                            tween:
                                Tween<double>(
                                  begin: 0,
                                  end:
                                      _totalProgress,
                                ),

                            duration:
                                const Duration(
                                  milliseconds:
                                      200,
                                ),

                            curve:
                                Curves.easeOut,

                            builder: (
                              context,
                              value,
                              child,
                            ) {
                              return CustomProgressBar(
                                progress:
                                    value,

                                borderRadius:
                                    5,
                              );
                            },
                          ),

                          AnimatedCrossFade(
                            crossFadeState:
                                _advanced
                                    ? CrossFadeState
                                        .showSecond
                                    : CrossFadeState
                                        .showFirst,

                            duration:
                                const Duration(
                                  milliseconds:
                                      200,
                                ),

                            alignment:
                                Alignment.topLeft,

                            firstChild:
                                Container(),

                            secondChild:
                                Padding(
                                  padding:
                                      const EdgeInsets.only(
                                        top: 10,
                                        bottom: 5,
                                      ),

                                  child: Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment
                                            .start,

                                    children: [
                                      Text(
                                        t
                                            .progressPage
                                            .total
                                            .count(
                                              curr:
                                                  _finishedFileCount,

                                              n:
                                                    _fileCount,
                                            ),
                                      ),

                                      Text(
                                        t
                                            .progressPage
                                            .total
                                            .size(
                                              curr:
                                                  _totalBytesSent
                                                      .asReadableFileSize,

                                              n:
                                                  _totalSize
                                                      .asReadableFileSize,
                                            ),
                                      ),

                                      if (!_finished &&
                                          _megabytesPerSecond >
                                              0)
                                        Text(
                                          t
                                              .progressPage
                                              .total
                                              .speed(
                                                speed:
                                                    '${_megabytesPerSecond.toStringAsFixed(1)} MB',
                                              ),
                                        ),
                                    ],
                                  ),
                                ),
                          ),

                          const SizedBox(
                            height: 5,
                          ),

                          Row(
                            mainAxisAlignment:
                                MainAxisAlignment.end,

                            children: [
                              TextButton.icon(
                                style:
                                    TextButton.styleFrom(
                                      foregroundColor:
                                          Theme.of(
                                                context,
                                              )
                                              .colorScheme
                                              .onSurface,
                                    ),

                                onPressed: () {
                                  setState(() {
                                    _advanced =
                                        !_advanced;
                                  });
                                },

                                icon:
                                    const Icon(
                                      Icons.info,
                                    ),

                                label:
                                    Text(
                                      _advanced
                                          ? t.general.hide
                                          : t.general.advanced,
                                    ),
                              ),

                              TextButton.icon(
                                style:
                                    TextButton.styleFrom(
                                      foregroundColor:
                                          Theme.of(
                                                context,
                                              )
                                              .colorScheme
                                              .onSurface,
                                    ),

                                onPressed:
                                    _cancelRequested &&
                                            !_finished
                                        ? null
                                        : _onClosePressed,

                                icon:
                                    Icon(
                                      _finished
                                          ? Icons
                                              .check_circle
                                          : Icons.close,
                                    ),

                                label:
                                    Text(
                                      _finished
                                          ? t.general.done
                                          : t.general.cancel,
                                    ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}