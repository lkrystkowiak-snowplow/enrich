package com.snowplowanalytics.snowplow.enrich.common.loaders

import cats.data.{Ior, NonEmptyList}
import cats.effect.kernel.Sync
import cats.syntax.functor._
import cats.syntax.foldable._
import com.snowplowanalytics.iglu.core.PartialSchemaKey
import com.snowplowanalytics.snowplow.badrows.BadRow
import com.snowplowanalytics.snowplow.enrich.common.utils.CryptoUtils
import com.snowplowanalytics.snowplow.badrows.{Failure, Payload, Processor}
import com.snowplowanalytics.snowplow.enrich.common.outputs.EnrichedEvent
import org.joda.time.DateTime

import java.time.Instant

trait CollectorHmacVerifier[F[_]] {
  def processEvents(
    payload: CollectorPayload,
    events: List[Ior[BadRow, EnrichedEvent]],
    processor: Processor,
    etlTstamp: DateTime
  ): F[List[Ior[BadRow, EnrichedEvent]]]
}

// TODO
// Verify ts from http header

object CollectorHmacVerifier {
  val SignatureHeaderName = "Snowplow-Signature"

  case class CollectorHeader(hmac: String)

  def apply[F[_]: Sync](
    enabled: Boolean,
    keys: List[String],
    schemas: List[PartialSchemaKey]
  ): CollectorHmacVerifier[F] =
    new CollectorHmacVerifier[F] {
      override def processEvents(
        payload: CollectorPayload,
        events: List[Ior[BadRow, EnrichedEvent]],
        processor: Processor,
        etlTstamp: DateTime
      ): F[List[Ior[BadRow, EnrichedEvent]]] = {
        def transformEvents: List[Ior[BadRow, EnrichedEvent]] =
          events.map {
            case e @ Ior.Left(_) => e
            case e @ Ior.Right(ee) =>
              if (isVerificationRequired(ee)) Ior.Left(createBadRow(processor, etlTstamp)) else e
            case e @ Ior.Both(_, ee) =>
              if (isVerificationRequired(ee)) Ior.Left(createBadRow(processor, etlTstamp)) else e
          }

        if (enabled)
          (payload.body, extractHeader(payload.context.headers)) match {
            case (Some(body), Some(h)) =>
              keys.findM(key => CryptoUtils.hmacSha256Verify(body, key, h.hmac)).map { k =>
                if (k.isDefined) events
                else transformEvents
              }
            case _ => Sync[F].pure(transformEvents)
          }
        else Sync[F].pure(events)
      }

      private def isVerificationRequired(event: EnrichedEvent): Boolean =
        schemas.exists(s => s.vendor == event.event_vendor && s.name == event.event_name && s.format == event.event_format)

      private def extractHeader(headers: List[String]): Option[CollectorHeader] =
        headers.flatMap { h =>
          h.split(":", 2) match {
            case Array(SignatureHeaderName, v) => Some(CollectorHeader(v.strip))
            case _ => None
          }
        }.headOption

      private def createBadRow(processor: Processor, etlTstamp: DateTime): BadRow =
        BadRow.GenericError(
          processor,
          Failure.GenericFailure(Instant.ofEpochMilli(etlTstamp.toInstant.getMillis), NonEmptyList.one("todo")),
          Payload.RawPayload("todo")
        )
    }

}
