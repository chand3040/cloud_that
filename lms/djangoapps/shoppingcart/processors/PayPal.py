"""
Implementation the PayPal processor.

To enable this implementation, add the following to lms.auth.json:

    CC_PROCESSOR_NAME = "PayPal"
    CC_PROCESSOR = {
        "PayPal": {
            "PURCHASE_ENDPOINT": "sandbox or live url of paypal",
            "CLIENT_ID": "<paypal client_id>",
            "CLIENT_SECRET": "<paypal client secret>",
            "MODE": "sandbox | live",
            "RETURN_URL": 'host/dashboard',
            "NOTIFY_URL": 'host/paypal',
            "CANCEL_URL": 'where to redirect if user cancels order'
        }
    }

"""
import time
import hmac
import binascii
import re
import json
import urlparse
import logging
from collections import OrderedDict, defaultdict
from decimal import Decimal, InvalidOperation
from hashlib import sha1
from textwrap import dedent
from django.conf import settings
from django.utils.translation import ugettext as _
from edxmako.shortcuts import render_to_string
from shoppingcart.models import Order
from shoppingcart.processors.exceptions import *
from shoppingcart.processors.helpers import get_processor_config
from microsite_configuration import microsite
from django.core.urlresolvers import reverse
from paypal.standard.models import ST_PP_COMPLETED, ST_PP_CANCELLED, ST_PP_DENIED
from paypal.standard.ipn.signals import valid_ipn_received
from paypal.standard.pdt.views import process_pdt

logger = logging.getLogger(__name__)

def process_postpay_callback(request):
    """
    The top level call to this module, basically
    This function is handed the callback request after the customer has entered the CC info and clicked "buy"
    on the external Hosted Order Page.
    It is expected to verify the callback and determine if the payment was successful.
    It returns {'success':bool, 'order':Order, 'error_html':str}
    If successful this function must have the side effect of marking the order purchased and calling the
    purchased_callbacks of the cart items.
    If unsuccessful this function should not have those side effects but should try to figure out why and
    return a helpful-enough error message in error_html.
    
    Author: Naresh Makwana
    created on: 07-Apr-2015
    """
    logger.info('Handling GET request %s', request.GET)
    logger.info('Handling POST request %s', request.POST)    
    pdt_obj, failed = process_pdt(request)
    logger.info('invoice %s', getattr(pdt_obj, 'invoice'))
    logger.info('mc_currency %s', getattr(pdt_obj, 'mc_currency'))
    logger.info('payment_status %s', getattr(pdt_obj, 'payment_status'))
    try:
        result = payment_accepted(pdt_obj)
        if result['accepted']:
            # SUCCESS CASE first, rest are some sort of oddity
            record_purchase(pdt_obj, result['order'])
            return {'success': True,
                    'order': result['order'],
                    'error_html': ''}
        else:
            return {'success': False,
                    'order': result['order'],
                    'error_html': get_processor_decline_html(pdt_obj)}
    except CCProcessorException as error:
        return {'success': False,
                'order': None,  # due to exception we may not have the order
                'error_html': get_processor_exception_html(error)}


def processor_hash(value):
    """
    Performs the base64(HMAC_SHA1(key, value)) used by CyberSource Hosted Order Page
    """
    shared_secret = get_processor_config().get('SHARED_SECRET', '')
    hash_obj = hmac.new(shared_secret.encode('utf-8'), value.encode('utf-8'), sha1)
    return binascii.b2a_base64(hash_obj.digest())[:-1]  # last character is a '\n', which we don't want


def sign(params, signed_fields_key='orderPage_signedFields', full_sig_key='orderPage_signaturePublic'):
    """
    params needs to be an ordered dict, b/c cybersource documentation states that order is important.
    Reverse engineered from PHP version provided by cybersource
    """
    merchant_id = get_processor_config().get('MERCHANT_ID', '')
    order_page_version = get_processor_config().get('ORDERPAGE_VERSION', '7')
    serial_number = get_processor_config().get('SERIAL_NUMBER', '')

    params['merchantID'] = merchant_id
    params['orderPage_timestamp'] = int(time.time() * 1000)
    params['orderPage_version'] = order_page_version
    params['orderPage_serialNumber'] = serial_number
    fields = u",".join(params.keys())
    values = u",".join([u"{0}={1}".format(i, params[i]) for i in params.keys()])
    fields_sig = processor_hash(fields)
    values += u",signedFieldsPublicSignature=" + fields_sig
    params[full_sig_key] = processor_hash(values)
    params[signed_fields_key] = fields

    return params


def verify_signatures(ipn_obj):
    """
    Use the signature we receive in the POST back from PayPal to verify
    the identity of the sender (PayPal) and that the contents of the message
    have not been tampered with.

    Args:
        params (dictionary): The POST parameters we received from PayPal.

    Returns:
        dict: Contains the parameters we will use elsewhere, converted to the
            appropriate types

    Raises:
        CCProcessorSignatureException: The calculated signature does not match
            the signature we received.

        CCProcessorDataException: The parameters we received from CyberSource were not valid
            (missing keys, wrong types)

    """

    # First see if the user cancelled the transaction
    # if so, then not all parameters will be passed back so we can't yet verify signatures
    if getattr(ipn_obj, 'payment_status') == ST_PP_CANCELLED:
        raise CCProcessorUserCancelled()

    #  if the user decline the transaction
    # if so, then amount will not be passed back so we can't yet verify signatures
    if getattr(ipn_obj, 'payment_status') == ST_PP_DENIED:
        raise CCProcessorUserDeclined()

    return ipn_obj


def render_purchase_form_html(cart, **kwargs):
    """
    Renders the HTML of the hidden POST form that must be used to initiate a purchase with CyberSource
    """
    return render_to_string('shoppingcart/paypal_form.html', {
        'action': get_purchase_endpoint(),
        'params': get_signed_purchase_params(cart),
    })


def get_signed_purchase_params(cart, **kwargs):
    return sign(get_purchase_params(cart))


def get_purchase_params(cart):
    cart_items = cart.orderitem_set.all()
    total_cost = cart.total_cost
    amount = "{0:0.2f}".format(total_cost)
    cart_items = cart.orderitem_set.all()

    params = OrderedDict()
    params['business'] = settings.PAYPAL_RECEIVER_EMAIL
    params['invoice'] = "{0:d}".format(cart.id)
    params['item_number'] = "{0:d}".format(cart.id)
    params['notify_url'] = get_processor_config().get('NOTIFY_URL', '')
    params['return'] = get_processor_config().get('RETURN_URL', '')
    params['cancel_return'] = get_processor_config().get('CANCEL_URL', '')
    params['currency_code'] = cart.currency.upper()
    params['orderPage_transactionType'] = 'sale'
    params['orderNumber'] = "{0:d}".format(cart.id)
    params['no_shipping'] = 1
    params['charset'] = 'utf-8'
    params['upload'] = 1

    for counter, cart_item in enumerate(cart_items):
        params['item_name_'+str(counter+1)] = cart_item.line_desc
        params['amount_'+str(counter+1)] = cart_item.list_price
        params['quantity_'+str(counter+1)] = cart_item.qty

    params['cmd'] = '_cart'

    return params


def get_purchase_endpoint():
    return get_processor_config().get('PURCHASE_ENDPOINT', '')


def payment_accepted(ipn_obj):
    """
    Check that paypal has accepted the payment
    params: a dictionary of POST parameters returned by paypal in their post-payment callback

    returns: true if the payment was correctly accepted, for the right amount
             false if the payment was not accepted

    raises: CCProcessorDataException if the returned message did not provide required parameters
            CCProcessorWrongAmountException if the amount charged is different than the order amount

    """
    #make sure required keys are present and convert their values to the right type
    valid_params = {}
    for key, key_type in [('invoice', int),
                          ('mc_currency', str),
                          ('payment_status', str)]:
        if not hasattr(ipn_obj, key):
            raise CCProcessorDataException(
                _("The payment processor did not return a required parameter: {0}").format(key)
            )
        try:
            valid_params[key] = key_type(getattr(ipn_obj, key))
        except ValueError:
            raise CCProcessorDataException(
                _("The payment processor returned a badly-typed value {0} for param {1}.").format(getattr(ipn_obj, key), key)
            )

    try:
        order = Order.objects.get(id=valid_params['invoice'])
    except Order.DoesNotExist:
        raise CCProcessorDataException(_("The payment processor accepted an order whose number is not in our system."))

    if valid_params['payment_status'] == ST_PP_COMPLETED:
        try:
            # Moved reading of charged_amount here from the valid_params loop above because
            # only 'ACCEPT' messages have a 'mc_gross' parameter
            charged_amt = Decimal(getattr(ipn_obj, 'mc_gross'))
        except InvalidOperation:
            raise CCProcessorDataException(
                _("The payment processor returned a badly-typed value {0} for param {1}.").format(
                    getattr(ipn_obj, 'mc_gross'), 'mc_gross'
                )
            )

        if charged_amt == order.total_cost and valid_params['mc_currency'] == order.currency.upper():
            return {'accepted': True,
                    'amt_charged': charged_amt,
                    'currency': valid_params['mc_currency'].lower(),
                    'order': order}
        else:
            raise CCProcessorWrongAmountException(
                _("The amount charged by the processor {0} {1} is different than the total cost of the order {2} {3}.")
                .format(
                    charged_amt,
                    valid_params['mc_currency'],
                    order.total_cost,
                    order.currency
                )
            )
    else:
        return {'accepted': False,
                'amt_charged': 0,
                'currency': 'usd',
                'order': order}


def record_purchase(ipn_obj, order):
    """
    Record the purchase and run purchased_callbacks
    """
    ccnum_str = getattr(ipn_obj, 'card_accountNumber', '')
    m = re.search("\d", ccnum_str)
    if m:
        ccnum = ccnum_str[m.start():]
    else:
        ccnum = "####"

    order.purchase(
        first=getattr(ipn_obj, 'first_name', ''),
        last=getattr(ipn_obj, 'last_name', ''),
        street1=getattr(ipn_obj, 'billTo_street1', ''),
        street2=getattr(ipn_obj, 'address_street', ''),
        city=getattr(ipn_obj, 'address_city', ''),
        state=getattr(ipn_obj, 'address_state', ''),
        country=getattr(ipn_obj, 'address_country', ''),
        postalcode=getattr(ipn_obj, 'billTo_postalCode', ''),
        ccnum=ccnum,
        cardtype=CARDTYPE_MAP[getattr(ipn_obj, 'card_cardType', 'UNKNOWN')],
        processor_reply_dump=dict(urlparse.parse_qsl(str(getattr(ipn_obj, 'query', 'UNKNOWN=UNKNOWN'))))
    )


def get_processor_decline_html(ipn_obj):
    """Have to parse through the error codes to return a helpful message"""

    # see if we have an override in the microsites
    payment_support_email = microsite.get_value('payment_support_email', settings.PAYMENT_SUPPORT_EMAIL)

    msg = _(
        "Sorry! Our payment processor did not accept your payment. "
        "The decision they returned was {decision_text}, "
        "and the reason was {reason_text}. "
        "You were not charged. "
        "Please try a different form of payment. "
        "Contact us with payment-related questions at {email}."
    )
    formatted = msg.format(
        decision_text='<span class="decision">{}</span>'.format(getattr(ipn_obj, 'payment_status')),
        reason_text='<span class="reason">{code}:{msg}</span>'.format(
            code=params['reasonCode'], msg=REASONCODE_MAP[getattr(ipn_obj,'reason_code')],
        ),
        email=payment_support_email,
    )
    return '<p class="error_msg">{}</p>'.format(formatted)


def get_processor_exception_html(exception):
    """Return error HTML associated with exception"""

    # see if we have an override in the microsites
    payment_support_email = microsite.get_value('payment_support_email', settings.PAYMENT_SUPPORT_EMAIL)
    if isinstance(exception, CCProcessorDataException):
        msg = _(
            "Sorry! Our payment processor sent us back a payment confirmation "
            "that had inconsistent data!"
            "We apologize that we cannot verify whether the charge went through "
            "and take further action on your order."
            "The specific error message is: {error_message}. "
            "Your credit card may possibly have been charged. "
            "Contact us with payment-specific questions at {email}."
        )
        formatted = msg.format(
            error_message='<span class="exception_msg">{msg}</span>'.format(
                msg=exception.message,
            ),
            email=payment_support_email,
        )
        return '<p class="error_msg">{}</p>'.format(formatted)
    elif isinstance(exception, CCProcessorWrongAmountException):
        msg = _(
            "Sorry! Due to an error your purchase was charged for "
            "a different amount than the order total! "
            "The specific error message is: {error_message}. "
            "Your credit card has probably been charged. "
            "Contact us with payment-specific questions at {email}."
        )
        formatted = msg.format(
            error_message='<span class="exception_msg">{msg}</span>'.format(
                msg=exception.message,
            ),
            email=payment_support_email,
        )
        return '<p class="error_msg">{}</p>'.format(formatted)
    elif isinstance(exception, CCProcessorSignatureException):
        msg = _(
            "Sorry! Our payment processor sent us back a corrupted message "
            "regarding your charge, so we are unable to validate that "
            "the message actually came from the payment processor. "
            "The specific error message is: {error_message}. "
            "We apologize that we cannot verify whether the charge went through "
            "and take further action on your order. "
            "Your credit card may possibly have been charged. "
            "Contact us with payment-specific questions at {email}."
        )
        formatted = msg.format(
            error_message='<span class="exception_msg">{msg}</span>'.format(
                msg=exception.message,
            ),
            email=payment_support_email,
        )
        return '<p class="error_msg">{}</p>'.format(formatted)

    # fallthrough case, which basically never happens
    return '<p class="error_msg">EXCEPTION!</p>'


CARDTYPE_MAP = defaultdict(lambda: "UNKNOWN")
CARDTYPE_MAP.update(
    {
        '001': 'Visa',
        '002': 'MasterCard',
        '003': 'American Express',
        '004': 'Discover',
        '005': 'Diners Club',
        '006': 'Carte Blanche',
        '007': 'JCB',
        '014': 'EnRoute',
        '021': 'JAL',
        '024': 'Maestro',
        '031': 'Delta',
        '033': 'Visa Electron',
        '034': 'Dankort',
        '035': 'Laser',
        '036': 'Carte Bleue',
        '037': 'Carta Si',
        '042': 'Maestro',
        '043': 'GE Money UK card'
    }
)

REASONCODE_MAP = defaultdict(lambda: "UNKNOWN REASON")
REASONCODE_MAP.update(
    {
        '100': _('Successful transaction.'),
        '101': _('The request is missing one or more required fields.'),
        '102': _('One or more fields in the request contains invalid data.'),
        '104': dedent(_(
            """
            The merchantReferenceCode sent with this authorization request matches the
            merchantReferenceCode of another authorization request that you sent in the last 15 minutes.
            Possible fix: retry the payment after 15 minutes.
            """)),
        '150': _('Error: General system failure. Possible fix: retry the payment after a few minutes.'),
        '151': dedent(_(
            """
            Error: The request was received but there was a server timeout.
            This error does not include timeouts between the client and the server.
            Possible fix: retry the payment after some time.
            """)),
        '152': dedent(_(
            """
            Error: The request was received, but a service did not finish running in time
            Possible fix: retry the payment after some time.
            """)),
        '201': _('The issuing bank has questions about the request. Possible fix: retry with another form of payment'),
        '202': dedent(_(
            """
            Expired card. You might also receive this if the expiration date you
            provided does not match the date the issuing bank has on file.
            Possible fix: retry with another form of payment
            """)),
        '203': dedent(_(
            """
            General decline of the card. No other information provided by the issuing bank.
            Possible fix: retry with another form of payment
            """)),
        '204': _('Insufficient funds in the account. Possible fix: retry with another form of payment'),
        # 205 was Stolen or lost card.  Might as well not show this message to the person using such a card.
        '205': _('Unknown reason'),
        '207': _('Issuing bank unavailable. Possible fix: retry again after a few minutes'),
        '208': dedent(_(
            """
            Inactive card or card not authorized for card-not-present transactions.
            Possible fix: retry with another form of payment
            """)),
        '210': _('The card has reached the credit limit. Possible fix: retry with another form of payment'),
        '211': _('Invalid card verification number. Possible fix: retry with another form of payment'),
        # 221 was The customer matched an entry on the processor's negative file.
        # Might as well not show this message to the person using such a card.
        '221': _('Unknown reason'),
        '231': _('Invalid account number. Possible fix: retry with another form of payment'),
        '232': dedent(_(
            """
            The card type is not accepted by the payment processor.
            Possible fix: retry with another form of payment
            """)),
        '233': _('General decline by the processor.  Possible fix: retry with another form of payment'),
        '234': _(
            "There is a problem with our CyberSource merchant configuration.  Please let us know at {0}"
        ).format(settings.PAYMENT_SUPPORT_EMAIL),
        # reason code 235 only applies if we are processing a capture through the API. so we should never see it
        '235': _('The requested amount exceeds the originally authorized amount.'),
        '236': _('Processor Failure.  Possible fix: retry the payment'),
        # reason code 238 only applies if we are processing a capture through the API. so we should never see it
        '238': _('The authorization has already been captured'),
        # reason code 239 only applies if we are processing a capture or credit through the API,
        # so we should never see it
        '239': _('The requested transaction amount must match the previous transaction amount.'),
        '240': dedent(_(
            """
            The card type sent is invalid or does not correlate with the credit card number.
            Possible fix: retry with the same card or another form of payment
            """)),
        # reason code 241 only applies when we are processing a capture or credit through the API,
        # so we should never see it
        '241': _('The request ID is invalid.'),
        # reason code 242 occurs if there was not a previously successful authorization request or
        # if the previously successful authorization has already been used by another capture request.
        # This reason code only applies when we are processing a capture through the API
        # so we should never see it
        '242': dedent(_(
            """
            You requested a capture through the API, but there is no corresponding, unused authorization record.
            """)),
        # we should never see 243
        '243': _('The transaction has already been settled or reversed.'),
        # reason code 246 applies only if we are processing a void through the API. so we should never see it
        '246': dedent(_(
            """
            The capture or credit is not voidable because the capture or credit information has already been
            submitted to your processor. Or, you requested a void for a type of transaction that cannot be voided.
            """)),
        # reason code 247 applies only if we are processing a void through the API. so we should never see it
        '247': _('You requested a credit for a capture that was previously voided'),
        '250': dedent(_(
            """
            Error: The request was received, but there was a timeout at the payment processor.
            Possible fix: retry the payment.
            """)),
        '520': dedent(_(
            """
            The authorization request was approved by the issuing bank but declined by CyberSource.'
            Possible fix: retry with a different form of payment.
            """)),
    }
)
