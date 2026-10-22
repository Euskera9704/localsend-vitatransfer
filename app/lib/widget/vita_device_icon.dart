import 'package:flutter/material.dart';

class VitaDeviceIcon extends StatelessWidget {
  final double size;

  const VitaDeviceIcon({
    super.key,
    this.size = 46,
  });

  @override
  Widget build(BuildContext context) {
    final color =
        IconTheme.of(context).color ??
        Theme.of(context).colorScheme.onSurface;

    return SizedBox(
      width: size,
      height: size,
      child: Center(
        child: CustomPaint(
          size: Size(
            size,
            size * 0.58,
          ),
          painter: _VitaDeviceIconPainter(
            color: color,
          ),
        ),
      ),
    );
  }
}

class _VitaDeviceIconPainter extends CustomPainter {
  final Color color;

  const _VitaDeviceIconPainter({
    required this.color,
  });

  @override
  void paint(
    Canvas canvas,
    Size size,
  ) {
    final strokeWidth =
        size.height * 0.075;

    final paint =
        Paint()
          ..color = color
          ..style = PaintingStyle.stroke
          ..strokeWidth = strokeWidth
          ..strokeCap = StrokeCap.round
          ..strokeJoin = StrokeJoin.round;

    final body =
        RRect.fromRectAndRadius(
          Rect.fromLTWH(
            strokeWidth / 2,
            strokeWidth / 2,
            size.width - strokeWidth,
            size.height - strokeWidth,
          ),
          Radius.circular(
            size.height * 0.43,
          ),
        );

    canvas.drawRRect(
      body,
      paint,
    );

    final screen =
        RRect.fromRectAndRadius(
          Rect.fromLTWH(
            size.width * 0.28,
            size.height * 0.17,
            size.width * 0.44,
            size.height * 0.66,
          ),
          Radius.circular(
            size.height * 0.07,
          ),
        );

    canvas.drawRRect(
      screen,
      paint,
    );

    // Stick izquierdo
    canvas.drawCircle(
      Offset(
        size.width * 0.16,
        size.height * 0.54,
      ),
      size.height * 0.105,
      paint,
    );

    // Cruceta
    canvas.drawLine(
      Offset(
        size.width * 0.095,
        size.height * 0.29,
      ),
      Offset(
        size.width * 0.205,
        size.height * 0.29,
      ),
      paint,
    );

    canvas.drawLine(
      Offset(
        size.width * 0.15,
        size.height * 0.20,
      ),
      Offset(
        size.width * 0.15,
        size.height * 0.38,
      ),
      paint,
    );

    // Botones derechos
    final buttonRadius =
        size.height * 0.035;

    canvas.drawCircle(
      Offset(
        size.width * 0.84,
        size.height * 0.28,
      ),
      buttonRadius,
      paint,
    );

    canvas.drawCircle(
      Offset(
        size.width * 0.89,
        size.height * 0.43,
      ),
      buttonRadius,
      paint,
    );

    canvas.drawCircle(
      Offset(
        size.width * 0.79,
        size.height * 0.43,
      ),
      buttonRadius,
      paint,
    );

    canvas.drawCircle(
      Offset(
        size.width * 0.84,
        size.height * 0.58,
      ),
      buttonRadius,
      paint,
    );

    // Stick derecho
    canvas.drawCircle(
      Offset(
        size.width * 0.84,
        size.height * 0.76,
      ),
      size.height * 0.09,
      paint,
    );
  }

  @override
  bool shouldRepaint(
    _VitaDeviceIconPainter oldDelegate,
  ) {
    return oldDelegate.color != color;
  }
}