package com.snowplowanalytics.snowplow.enrich.common.utils

import cats.effect.kernel.Sync
import cats.syntax.functor._

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import scodec.bits.ByteVector

object CryptoUtils {
  val HmacSHA256Algorithm = "HmacSHA256"

  def hmacSha256[F[_]: Sync](data: ByteVector, key: String): F[ByteVector] =
    Sync[F].catchNonFatal {
      val mac = Mac.getInstance(HmacSHA256Algorithm)
      val sk = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HmacSHA256Algorithm)
      mac.init(sk)
      mac.update(data.toByteBuffer)
      ByteVector.view(mac.doFinal())
    }

  def hmacSha256Verify[F[_]: Sync](
    data: String,
    key: String,
    hmacInHex: String
  ): F[Boolean] =
    ByteVector.encodeString(data)(StandardCharsets.UTF_8) match {
      case Left(err) => Sync[F].raiseError(err)
      case Right(dataBv) => hmacSha256(dataBv, key).map(_.toHex == hmacInHex)
    }
}
